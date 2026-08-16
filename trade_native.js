'use strict';
// ---------------------------------------------------------------------------
// Native trading transport (desktop shell) — Phemex / Binance / Bybit /
// OKX / Gate / Bitget, spot + USDT-M futures.
// ---------------------------------------------------------------------------
// The renderer NEVER sees API keys and NEVER builds requests: it sends an
// order INTENT over IPC (att:trade-exec) and the main process validates it
// hard, builds the canonical exchange request with the pure builders below
// (golden-vector parity-tested against terminal_engine.py), signs it with
// creds held ONLY here (Electron safeStorage at rest), and sends it through
// the same proxy-agent routing as the native market-data sockets
// (nativeProxyUrl + routeNorm — proxy enabled but unbuildable agent REFUSES,
// it never dials direct past an enabled proxy).
//
// NO cross-transport fallback: a failed native order surfaces the error to
// the renderer verbatim-shaped ({ok:false, message}) and stops. Auto-retrying
// through the server path could double-fill.
//
// Everything above module.exports is PURE (no electron / no network) so the
// parity + validation tests can require() this file under plain node.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
const https = require('https');
const path = require('path');
const fs = require('fs');
const { nativeProxyUrl } = require('./proxy_url');

const { routeNorm, VENUE_ROUTE_HOSTS } = require('./route_hosts');
const dexSign = require('./dex_sign.js');
// #2272 KuCoin bullet dance — the SAME pure validators the public market-data
// bridge uses (wss-only + *.kucoin.com), so the private lane cannot become an
// arbitrary-socket primitive either.
const { kcBulletParse, kcDialUrl } = require('./kucoin_bullet');

let SocksProxyAgent = null, HttpsProxyAgent = null;
try { SocksProxyAgent = require('socks-proxy-agent').SocksProxyAgent; } catch (e) { /* optional */ }
try { HttpsProxyAgent = require('https-proxy-agent').HttpsProxyAgent; } catch (e) { /* optional */ }

// ---------------------------------------------------------------------------
// Shared keep-alive agent cache — one warm agent per (scheme, proxyUrl) plus
// one shared direct https.Agent, so every native HTTPS request reuses an
// already-established connection instead of paying SOCKS handshake + TCP +
// TLS per request (~2-3 extra RTTs; +250-350 ms on a long proxy chain).
// Keyed by the FULL proxy URL: a proxy config change produces a different key
// (and flushKeepAliveAgents() is called on every change/disable anyway, so
// stale agents never linger and never dial the old egress).
// scheduling 'lifo' keeps the reuse window short (most-recently-used socket
// first → idle sockets age out at keepAliveMsecs) which minimizes the chance
// of writing into a server-killed socket.
// ---------------------------------------------------------------------------
const KEEPALIVE_MSECS = 15000;
// Cap concurrent sockets per agent (= per proxy config). Without a cap Node's
// http.Agent NEVER queues onto warm sockets — every concurrent request in a
// burst dials a brand-new SOCKS+TCP+TLS tunnel (empirically proven with
// req.reusedSocket harnesses), flooding the proxy chain and dropping some
// mid-TLS ("disconnected before secure TLS"). 4 warm lanes absorb scalping
// bursts while forcing reuse.
const KA_MAX_SOCKETS = 4;
const _kaAgents = new Map();   // 'direct' | '<scheme>|<proxyUrl>' → Agent
// Warm-up bookkeeping keyed per venue+HOST (split-REST-host venues — kraken
// api./futures., mexc api./contract., binance, kucoin, asterdex — must warm
// EVERY host their orders can dial, not just the futures one). Value = last
// warm attempt ms so opportunistic re-warms (board open / window focus) are
// rate-limited without any timer loop. Cleared on agent flush.
let _kaWarmed = new Map();     // '<venue>|<host>' → last warm ts (ms)

function kaAgentKey(scheme, proxyUrl) {
  return proxyUrl ? String(scheme) + '|' + String(proxyUrl) : 'direct';
}

// Returns the shared agent for the route, constructing it on first use.
// null = no agent buildable for a proxy route (module missing / ctor threw)
// — callers must keep their existing REFUSE semantics on null.
function sharedKeepAliveAgent(scheme, proxyUrl) {
  const key = kaAgentKey(scheme, proxyUrl);
  const hit = _kaAgents.get(key);
  if (hit) return hit;
  const opts = { keepAlive: true, keepAliveMsecs: KEEPALIVE_MSECS, scheduling: 'lifo',
                 maxSockets: KA_MAX_SOCKETS };
  let ag = null;
  try {
    if (!proxyUrl) ag = new https.Agent(opts);
    else if (scheme === 'socks5' && SocksProxyAgent) ag = new SocksProxyAgent(proxyUrl, opts);
    else if (scheme === 'http' && HttpsProxyAgent) ag = new HttpsProxyAgent(proxyUrl, opts);
    // agent-base (SocksProxyAgent / HttpsProxyAgent) computes the connection
    // pool name via a stack-trace sniff in isSecureEndpoint(): at addRequest
    // time the stack contains node:https (→ long TLS pool name) but the
    // deferred createSocket runs off a clean Promise stack (→ short name).
    // Freed sockets land under the short key, lookups use the long key —
    // so keepAlive NEVER reuses and, with maxSockets set, queued bursts
    // DEADLOCK (empirically proven with a local SOCKS5 relay harness). We
    // only ever dial HTTPS/wss venue hosts, so pinning secure=true on the
    // instance makes both sides compute the same name and pooling works.
    if (ag && proxyUrl) ag.isSecureEndpoint = () => true;
  } catch (e) { ag = null; }
  if (ag) _kaAgents.set(key, ag);
  return ag;
}

// Destroy + drop every cached agent (proxy config change / disable) so the
// next request dials fresh through the new egress.
function flushKeepAliveAgents() {
  for (const ag of _kaAgents.values()) {
    try { ag.destroy(); } catch (e) { /* non-fatal */ }
  }
  _kaAgents.clear();
  _kaWarmed.clear();   // warmth re-establishes on next arm/action — no timer loop
}

// --- stale-socket retry policy (pure) --------------------------------------
// A reused keep-alive socket can be killed by the venue between requests: the
// first write then fails with a transport error instead of a clean response.
// Retry budget by METHOD: GETs + time probes are read-only (retry once on a
// fresh socket), DELETE cancels are idempotent (venues answer "already gone"
// — gone-matchers handle that), but order-placing POSTs must NEVER be blind
// retried (double-fill risk) — they surface the error honestly.
function httpRetryLimit(method) {
  const m = String(method || '').toUpperCase();
  return (m === 'GET' || m === 'DELETE') ? 1 : 0;
}

// Errors that mean "the reused socket was already dead", not a venue verdict.
function staleSocketError(err) {
  if (!err) return false;
  const code = err.code;
  if (code === 'ECONNRESET' || code === 'EPIPE') return true;
  const em = String(err.message || '');
  return /\b(ECONNRESET|EPIPE)\b/.test(em) || /socket hang up/i.test(em);
}

// CONNECT-PHASE failures: the tunnel/TLS never came up, so the request body
// was NEVER transmitted — retrying is safe for ALL methods including order
// POSTs (nothing reached the venue; no double-fill risk). Matches the exact
// mid-TLS drop the proxy chain produces under burst dialing, plus refused /
// unreachable dials and SOCKS/proxy handshake errors. Pure — node-testable.
function connectPhaseError(err) {
  if (!err) return false;
  const code = err.code;
  if (code === 'ECONNREFUSED' || code === 'EHOSTUNREACH' || code === 'ENETUNREACH') return true;
  const em = String(err.message || '');
  return /disconnected before secure TLS/i.test(em) ||
         /\b(ECONNREFUSED|EHOSTUNREACH|ENETUNREACH)\b/.test(em) ||
         /socks/i.test(em) ||                      // SOCKS handshake/relay errors
         /proxy connection/i.test(em);             // HttpsProxyAgent CONNECT failures
}

// Retry decision by failure PHASE, not just method (pure — node-testable):
// - sent=false (request never flushed to the wire) + connect-phase or
//   dead-socket error → retry once for ANY method, POST included.
// - sent=true (request hit the wire) → keep the strict matrix: GET/DELETE
//   retry once on dead-socket errors only; POST never (double-fill risk).
function httpRetryAllowed(method, err, sent) {
  if (!sent && (connectPhaseError(err) || staleSocketError(err))) return true;
  return httpRetryLimit(method) > 0 && staleSocketError(err);
}

const PHEMEX_BASE = 'https://api.phemex.com';
const PHEMEX_HOST = 'api.phemex.com';
const PHEMEX_EXPIRY_S = 60;
const HTTP_TIMEOUT_MS = 12000;
// #2281 Phemex account-read budget. Phemex is by far the worst citizen of the
// shared pool (field capture 2026-08-16: 480 reads, p50 2,340 ms, p90 4,912 ms,
// max 16,828 ms — ~1,196 s of pool wall time, a quarter of the whole session's
// budget on one venue), and its read is four-plus SEQUENTIAL signed legs, so
// the generic 12 s transport timeout let a single hung leg hold the venue's
// share of the pool for most of a minute. The read now carries a hard overall
// DEADLINE and each leg's socket timeout is clamped to whatever is left of it,
// so a hung request is abandoned long before it can wedge anything. Applies to
// the background account-read lane ONLY — order placement, cancellation and
// the fill-recording legs keep the full HTTP_TIMEOUT_MS.
const PHEMEX_ACCT_LEG_MS = 4000;
const PHEMEX_ACCT_DEADLINE_MS = 7000;
// #2281 per-ATTEMPT socket timeout under an ABSOLUTE deadline. Returns the
// smaller of the caller's own per-attempt cap and whatever is LEFT of the
// deadline; a result of 0 or less means "the budget is spent — do not open a
// socket at all". Re-evaluated per attempt rather than once per call, so
// httpJson's one phase-aware retry can only ever spend the REMAINDER of the
// deadline instead of being handed a second full timeout (which is how a
// nominally 7 s read could otherwise run past 20 s and keep holding its share
// of the shared pool). No deadline ⇒ the caller's cap ⇒ today's behavior.
function httpTmoAt(timeoutMs, deadlineAt, now) {
  const base = (Number.isFinite(timeoutMs) && timeoutMs > 0)
    ? Math.min(timeoutMs, HTTP_TIMEOUT_MS) : HTTP_TIMEOUT_MS;
  if (!(Number.isFinite(deadlineAt) && deadlineAt > 0)) return base;
  return Math.min(base, deadlineAt - now);
}
const PRODUCTS_TTL_MS = 10 * 60 * 1000;
const TIMESYNC_TTL_MS = 10 * 60 * 1000;

// Venues this module can trade natively. The registry keys everything
// (validation, signer pick, creds slots) so adding a venue is additive.
const TRADE_VENUES = ['phemex', 'binance', 'bybit', 'okx', 'gate', 'bitget', 'kucoin', 'bitmex',
                      'mexc', 'hyperliquid', 'asterdex', 'arcus', 'lighter', 'kraken'];
// Multi-account creds SLOT grammar (pure): 'venue' (default account) or
// 'venue#aN' (extra account, same grammar as the device key vault / panel
// termVK). Returns {slot, base} — base keys HOSTS/agents/warmth (per venue),
// slot keys CREDS (per account). null = not a valid slot ('bad-venue').
// Strict fail-closed: a composite slot NEVER falls back to the base venue's
// creds — a wrong-account order is worse than a refusal.
function tnSlotNorm(v) {
  const s = String(v == null ? '' : v);
  const m = /^([a-z]+)(#a\d{1,4})?$/.exec(s);
  if (!m || TRADE_VENUES.indexOf(m[1]) < 0) return null;
  return { slot: s, base: m[1] };
}
// DEX venues carry symbols the CEX charset forbids: HL spot 'UBTC/USDC',
// HIP-3 builder perps 'xyz:PLTR', spot wire '@N'.
const DEX_VENUES = ['hyperliquid', 'asterdex', 'arcus'];
const HL_HOST = 'api.hyperliquid.xyz';
const ASTER_FUT_HOST = 'fapi.asterdex.com';
const ASTER_SPOT_HOST = 'sapi.asterdex.com';
const ARCUS_HOST = 'api.arcus.xyz';
const ARCUS_MARK_MAX_AGE_MS = 5000;   // market orders need a FRESH mark bound
const DEX_PRODUCTS_TTL_MS = 10 * 60 * 1000;

// Cryptic Phemex codes → clear panel messages (subset parity with the engine).
const PHEMEX_ERRORS = {
  10001: 'Duplicate order ID',
  10002: 'Phemex system is busy — try again',
  10004: 'Rate limited by Phemex — retry shortly',
  11001: 'Insufficient available balance',
  11003: 'Risk limit exceeded',
  11005: 'Insufficient available balance',
  11010: 'Order price is out of range',
  11012: 'Order would immediately liquidate the position',
  11014: 'Order quantity below the minimum',
  11015: 'Order quantity above the maximum',
  11041: 'Order price too far from the mark price',
  11057: 'Reduce-only order would increase the position',
  11077: 'Too many active orders for this symbol',
  20004: 'Phemex has this symbol in Hedge mode — the app trades One-Way only',
  30000: 'Phemex rejected the request arguments',
  39995: 'Rate limited by Phemex — retry shortly',
  39996: 'Invalid or expired request signature',
  39997: 'Invalid API key',
  39998: 'Request expired — check server clock',
  39999: 'Phemex system error — try again',
};

function phemexErrorMessage(code, rawMsg) {
  const m = PHEMEX_ERRORS[Number(code)];
  if (m) return m;
  return 'Phemex error ' + code + (rawMsg ? ': ' + rawMsg : '');
}

// #1722: symbol-required error family — some Phemex deployments answer the
// currency-wide /g-orders/activeList (and /spot/orders) queries with code
// 10500 ("Missing required parameter,Required query parameter 'symbol' is
// not present.") instead of the known 30000. Both codes, plus any message
// naming the missing-symbol condition, trigger the per-symbol fallback;
// everything else (auth/permission/transport) stays fail-closed. Pure —
// engine twin: phemex_symbol_required.
function phemexSymbolRequired(r) {
  if (!r || r.ok) return false;
  const c = Number(r.code);
  if (c === 30000 || c === 10500) return true;
  return /symbol.*not present|missing required parameter/i.test(String(r.message || ''));
}

// ---------------------------------------------------------------------------
// Pure numeric helpers — byte-parity with terminal_engine.py (Decimal-based).
// ---------------------------------------------------------------------------
// Canonical decimal split: "  -1.2500e2 " → {neg, int:'125', frac:''}.
// Accepts optional exponent (Python Decimal does); throws on garbage.
function decParts(value) {
  const s = String(value == null ? '' : value).trim();
  const m = /^([+-]?)(\d+)?(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(s);
  if (!m || (m[2] === undefined && m[3] === undefined)) {
    throw new Error('invalid decimal: ' + s);
  }
  let neg = m[1] === '-';
  let ip = m[2] || '0';
  let fp = m[3] || '';
  const exp = m[4] ? parseInt(m[4], 10) : 0;
  if (exp) {
    let digits = ip + fp;
    let point = ip.length + exp;            // digits before the decimal point
    if (point <= 0) { digits = '0'.repeat(1 - point) + digits; point = 1; }
    if (point >= digits.length) { digits = digits + '0'.repeat(point - digits.length); }
    ip = digits.slice(0, point);
    fp = digits.slice(point);
  }
  ip = ip.replace(/^0+(?=\d)/, '');
  return { neg, ip, fp };
}

// Real decimal string normalized like Python format(Decimal(x).normalize(),'f')
// — trailing fractional zeros trimmed, integer values stay plain ("100").
function futReal(value) {
  const { neg, ip, fp } = decParts(value);
  const f = fp.replace(/0+$/, '');
  const body = f ? ip + '.' + f : ip;
  const zero = /^0(\.0*)?$/.test(body);
  return (neg && !zero ? '-' : '') + body;
}

// Real decimal → e-scaled integer (Phemex spot). Throws when the value does
// not land on an integer at the given scale (parity with spot_to_scaled).
function spotToScaled(value, scale) {
  const sc = scale == null ? 8 : Number(scale);
  if (!Number.isInteger(sc) || sc < 0 || sc > 18) throw new Error('bad scale');
  const { neg, ip, fp } = decParts(value);
  const fpad = fp + '0'.repeat(Math.max(0, sc - fp.length));
  const rest = fpad.slice(sc);
  if (/[1-9]/.test(rest)) {
    throw new Error('value ' + value + ' is not representable at 1e' + sc + ' scale');
  }
  const digits = (ip + fpad.slice(0, sc)).replace(/^0+(?=\d)/, '');
  const n = Number((neg ? '-' : '') + digits);
  if (!Number.isSafeInteger(n)) throw new Error('scaled value overflows');
  return n;
}

// ---------------------------------------------------------------------------
// Phemex signing (pure)
// ---------------------------------------------------------------------------
function phemexSign(secret, reqPath, query, expiry, body) {
  const msg = String(reqPath) + String(query || '') + String(expiry) + String(body || '');
  return crypto.createHmac('sha256', String(secret)).update(msg, 'utf8').digest('hex');
}

function phemexExpiry(nowSec, offsetSec) {
  const now = (nowSec != null ? nowSec : Date.now() / 1000) + (offsetSec || 0);
  return Math.floor(now) + PHEMEX_EXPIRY_S;
}

// ---------------------------------------------------------------------------
// Phemex order-body builders (pure — parity with terminal_engine.py)
// ---------------------------------------------------------------------------
const PHE_TYPE_MAP = { market: 'Market', limit: 'Limit', stop: 'Stop',
                       stop_limit: 'StopLimit', tp_market: 'MarketIfTouched' };

function phemexFuturesOrderBody(symbol, side, ordType, qty, price, clOrdID, flags) {
  const f = flags || {};
  const sideP = String(side).toLowerCase() === 'buy' ? 'Buy' : 'Sell';
  const typ = PHE_TYPE_MAP[String(ordType).toLowerCase()] || 'Limit';
  const body = {
    symbol: symbol,
    clOrdID: clOrdID,
    side: sideP,
    ordType: typ,
    orderQtyRq: futReal(qty),
    posSide: 'Merged',
  };
  if (typ === 'Limit' || typ === 'StopLimit') {
    body.priceRp = futReal(price);
    body.timeInForce = 'GoodTillCancel';
  } else {
    body.timeInForce = 'ImmediateOrCancel';
  }
  if (typ === 'Stop' || typ === 'StopLimit' || typ === 'MarketIfTouched') {
    body.stopPxRp = futReal(f.trigger);
    body.triggerType = 'ByLastPrice';
  }
  if (f.reduceOnly) body.reduceOnly = true;
  if (f.closeOnTrigger) body.closeOnTrigger = true;
  return body;
}

// Spot body. baseVs = the BASE currency's valueScale (per-currency, NOT a
// flat 1e8 — 1000MOG=4, PEPE/SHIB=2); prices + quote-side Ev stay 1e8.
// Spot market BUY spends quote currency: qty = USDT amount (ByQuote, IOC).
function phemexSpotOrderBody(symbol, side, ordType, qty, price, clOrdID, baseVs) {
  const sideP = String(side).toLowerCase() === 'buy' ? 'Buy' : 'Sell';
  const typ = String(ordType).toLowerCase() === 'market' ? 'Market' : 'Limit';
  const vs = Number.isInteger(baseVs) ? baseVs : 8;
  const body = {
    symbol: symbol,
    clOrdID: clOrdID,
    side: sideP,
    ordType: typ,
  };
  if (typ === 'Limit') {
    body.priceEp = spotToScaled(price, 8);
    body.qtyType = 'ByBase';
    body.baseQtyEv = spotToScaled(qty, vs);
    body.timeInForce = 'GoodTillCancel';
  } else {
    if (sideP === 'Buy') {
      body.qtyType = 'ByQuote';
      body.quoteQtyEv = spotToScaled(qty, 8);
    } else {
      body.qtyType = 'ByBase';
      body.baseQtyEv = spotToScaled(qty, vs);
    }
    body.timeInForce = 'ImmediateOrCancel';
  }
  return body;
}

// Compact JSON — byte parity with Python json.dumps(separators=(",",":")).
function canonJson(obj) {
  return JSON.stringify(obj);
}

// One intent → the canonical Phemex request(s). Returns a LIST of
// {method, path, query, body} steps executed in order (cancel_all futures
// sweeps both order books). `spec` carries {value_scale} for spot symbols.
function buildPhemexRequests(intent, spec) {
  const market = intent.market === 'spot' ? 'spot' : 'futures';
  const op = intent.op;
  if (op === 'order') {
    if (market === 'spot') {
      const t = String(intent.type).toLowerCase();
      if (t !== 'limit' && t !== 'market') throw new Error('Stop orders are futures-only');
      const vs = spec && Number.isInteger(spec.value_scale) ? spec.value_scale : 8;
      return [{ method: 'POST', path: '/spot/orders', query: '',
                body: phemexSpotOrderBody(intent.symbol, intent.side, intent.type,
                                          intent.qty, intent.price, intent.clOrdID, vs) }];
    }
    return [{ method: 'POST', path: '/g-orders', query: '',
              body: phemexFuturesOrderBody(intent.symbol, intent.side, intent.type,
                                           intent.qty, intent.price, intent.clOrdID,
                                           { reduceOnly: !!intent.reduceOnly,
                                             trigger: intent.trigger,
                                             closeOnTrigger: !!intent.closeOnTrigger }) }];
  }
  if (op === 'cancel') {
    if (market === 'spot') {
      return [{ method: 'DELETE', path: '/spot/orders',
                query: 'symbol=' + intent.symbol + '&orderID=' + intent.orderID, body: null }];
    }
    return [{ method: 'DELETE', path: '/g-orders/cancel',
              query: 'symbol=' + intent.symbol + '&orderID=' + intent.orderID + '&posSide=Merged',
              body: null }];
  }
  if (op === 'cancel_all') {
    if (market === 'spot') {
      return [{ method: 'DELETE', path: '/spot/orders/all',
                query: 'symbol=' + intent.symbol, body: null }];
    }
    // Sweep BOTH books: working limits AND untriggered conditionals.
    return [
      { method: 'DELETE', path: '/g-orders/all',
        query: 'symbol=' + intent.symbol + '&untriggered=false', body: null },
      { method: 'DELETE', path: '/g-orders/all',
        query: 'symbol=' + intent.symbol + '&untriggered=true', body: null },
    ];
  }
  throw new Error('unknown op');
}

// --- Phemex hedge-mode (20004) recovery -------------------------------------
// posSide:'Merged' orders require the symbol in ONE-WAY position mode; a user
// who flipped the symbol to Hedge in the Phemex app gets every order rejected
// with 20004 TE_ERR_INCONSISTENT_POS_MODE. Recovery: switch the symbol back to
// one-way via the documented endpoint, then retry the original request ONCE.
// NO proactive probe — zero happy-path latency (unlike the Binance guard).
function phemexSwitchPosModeStep(symbol) {
  return { method: 'PUT', path: '/g-positions/switch-pos-mode-sync',
           query: 'symbol=' + symbol + '&targetPosMode=OneWay', body: null };
}

// Pure recovery flow (node-testable): `send(step)` is the signed-request
// runner. Non-20004 rejects pass through UNCHANGED; on 20004 the switch is
// attempted and the original step retried exactly once; a failed switch
// (Phemex refuses while hedge positions/active orders exist) returns a clear
// actionable message. Never loops.
async function phemexHedgeRecoveryFlow(send, step) {
  const r = await send(step);
  if (!r || r.ok || Number(r.code) !== 20004) return r;
  const sym = String((step && step.body && step.body.symbol) || '');
  const sw = await send(phemexSwitchPosModeStep(sym));
  if (!sw || !sw.ok) {
    return { ok: false, code: 20004,
             message: 'Phemex has ' + (sym || 'this symbol') + ' in Hedge mode and it could not '
                    + 'be switched automatically — close hedge positions/orders and switch to '
                    + 'One-Way in Phemex settings, then retry' };
  }
  return await send(step);
}

// ---------------------------------------------------------------------------
// Pure positions parser (parity with phemex_position_rows) — used by the
// close / sltp flows. Accepts BOTH `size` and `sizeRq` spellings.
// ---------------------------------------------------------------------------
function phemexPositionRows(data) {
  const rows = [];
  const list = (data && Array.isArray(data.positions)) ? data.positions : [];
  for (const p of list) {
    try {
      const size = numStr(p.sizeRq) || numStr(p.size) || '0';
      if (Number(size) === 0) continue;
      rows.push({
        symbol: p.symbol, side: p.side, size: size,
        mark: numStr(p.markPriceRp),
      });
    } catch (e) { /* skip bad row */ }
  }
  return rows;
}

function numStr(v) {
  if (v == null) return null;
  const s = String(v).trim().split(' ')[0];
  try { decParts(s); return s; } catch (e) { return null; }
}

function findPosition(rows, symbol) {
  for (const r of rows) if (r.symbol === symbol) return r;
  const lo = String(symbol).toLowerCase();
  for (const r of rows) if (String(r.symbol).toLowerCase() === lo) return r;
  return null;
}

// ---------------------------------------------------------------------------
// Hard intent validation (main-process side — never trust renderer strings).
// Returns null when valid, else a human-readable reason.
// ---------------------------------------------------------------------------
const _DEC_RE = /^[+-]?\d+(\.\d+)?$/;

function decOk(v) { return typeof v === 'string' && v.length <= 32 && _DEC_RE.test(v); }
function posDecOk(v) { return decOk(v) && Number(v) > 0; }

function validateIntent(it) {
  if (!it || typeof it !== 'object') return 'bad intent';
  if (TRADE_VENUES.indexOf(it.venue) < 0) return 'venue not supported natively';
  // Optional per-account creds slot (aid>0 boards send credSlot='venue#aN');
  // it must parse AND belong to the intent's venue — never another venue's key.
  if (it.credSlot != null) {
    const sn = tnSlotNorm(it.credSlot);
    if (!sn || sn.base !== it.venue) return 'bad credSlot';
  }
  if (['order', 'cancel', 'cancel_all', 'close', 'sltp', 'amend'].indexOf(it.op) < 0) return 'unknown op';
  const market = it.market;
  if (it.op !== 'close' && it.op !== 'sltp' && market !== 'spot' && market !== 'futures') {
    return 'market must be spot or futures';
  }
  const sym = it.symbol;
  const symRe = DEX_VENUES.indexOf(it.venue) >= 0
    ? /^[A-Za-z0-9._:/@-]+$/
    : (it.venue === 'kraken' ? /^[A-Za-z0-9./_-]+$/ : /^[A-Za-z0-9._-]+$/);
  if (typeof sym !== 'string' || !sym || sym.length > 32 || !symRe.test(sym)) {
    return 'bad symbol';
  }
  if (it.op === 'order') {
    if (it.side !== 'buy' && it.side !== 'sell') return 'bad side';
    const t = it.type;
    if (['limit', 'market', 'stop', 'stop_limit', 'tp_market'].indexOf(t) < 0) return 'bad type';
    const isStop = t === 'stop' || t === 'stop_limit' || t === 'tp_market';
    if (isStop && market !== 'futures') return 'Stop orders are futures-only';
    if (isStop && !posDecOk(it.trigger)) return 'bad trigger';
    if (!posDecOk(it.qty)) return 'bad qty';
    if ((t === 'limit' || t === 'stop_limit') && !posDecOk(it.price)) return 'bad price';
    if (typeof it.clOrdID !== 'string' || !it.clOrdID || it.clOrdID.length > 64) return 'bad clOrdID';
  }
  if (it.op === 'cancel') {
    if (typeof it.orderID !== 'string' || !it.orderID || it.orderID.length > 64
        || !/^[A-Za-z0-9:_-]+$/.test(it.orderID)) return 'bad orderID';
  }
  if (it.op === 'close') {
    if (typeof it.clOrdID !== 'string' || !it.clOrdID || it.clOrdID.length > 64) return 'bad clOrdID';
  }
  if (it.op === 'amend') {
    // #1864 replace gesture: kraken-only for now (spot WS-v2 amend_order)
    if (it.venue !== 'kraken') return 'amend not supported on this venue';
    if (typeof it.orderID !== 'string' || !it.orderID || it.orderID.length > 64
        || !/^[A-Za-z0-9:_-]+$/.test(it.orderID)) return 'bad orderID';
    if (!posDecOk(it.price)) return 'bad price';
  }
  if (it.op === 'sltp') {
    if (it.kind !== 'sl' && it.kind !== 'tp') return 'bad kind';
    if (!posDecOk(it.trigger)) return 'bad trigger';
    if (typeof it.clOrdID !== 'string' || !it.clOrdID || it.clOrdID.length > 64) return 'bad clOrdID';
  }
  return null;
}

// SL/TP trigger sanity vs the position side + mark (parity with the engine's
// sltp_trigger_ok): SL sits on the LOSS side of mark, TP on the PROFIT side.
// Confirmed-path echo for a trade exec response: derives WHAT ACTUALLY
// happened from the agent pick (never from the requested pref). An agent
// present = the tunnel is really in use; no agent = the request goes over
// the plain internet; refuse = the send was REFUSED (proxy enabled but no
// agent buildable — never silently direct). Pure — node-testable.
function tradeViaFromAgent(ag) {
  if (ag && ag.refuse) return { transport: 'native', refused: true };
  return { transport: 'native', route: (ag && ag.agent) ? 'proxy' : 'direct' };
}

// Read-only latency-probe target per venue+market (op:'ping_rt') — one cheap
// PUBLIC endpoint on the SAME REST host the venue's orders dial (no keys, no
// signing, no order). Reuses the venue time-probe registry where one exists;
// the two venues without a public time endpoint get their own cheap GET/POST.
// Pure — node-testable. null = venue has no probe target (panel skips).
function pingRtTarget(venue, market) {
  const p = venueTimeProbe(venue, market);
  if (p) return { host: p.host, method: 'GET', path: p.path, body: null };
  if (venue === 'hyperliquid') {
    // HL has no GET time endpoint — /info is POST-only; "meta" is the
    // cheapest public query and rides the exact host orders use.
    return { host: HL_HOST, method: 'POST', path: '/info', body: '{"type":"meta"}' };
  }
  if (venue === 'arcus') {
    // Arcus health endpoint lives at /health (NOT under /v1).
    return { host: ARCUS_HOST, method: 'GET', path: '/health', body: null };
  }
  return null;
}

// Warm-up target list per venue — EVERY distinct REST host the venue's
// orders can dial (split-host venues resolve different pingRtTarget hosts per
// market; single-host venues dedupe to one entry). Each entry carries the
// market whose probe it rode so callers can feed the matching clock-offset
// cache when the target IS the venue time endpoint. key = venue+'|'+host —
// per-host warm bookkeeping. Pure — node-testable.
function warmTargetsFor(venue) {
  const out = [];
  const seen = {};
  for (const mk of ['futures', 'spot']) {
    const t = pingRtTarget(venue, mk);
    if (!t || seen[t.host]) continue;
    seen[t.host] = true;
    out.push({ key: venue + '|' + t.host, host: t.host, method: t.method,
               path: t.path, body: t.body, market: mk });
  }
  return out;
}

// Opportunistic re-warm rate limit: warm sockets die after idle
// (proxy/CF keep-alive timeouts), so cheap user signals (board open, window
// focus) re-warm — but at most once per WARM_MIN_GAP_MS per venue+host.
// last == null/undefined/0 → never warmed → due. Pure — node-testable.
const WARM_MIN_GAP_MS = 60 * 1000;
function rewarmDue(lastMs, nowMs, minGapMs) {
  const gap = (minGapMs == null) ? WARM_MIN_GAP_MS : Number(minGapMs);
  if (!lastMs) return true;
  return (Number(nowMs) - Number(lastMs)) >= gap;
}

function sltpTriggerOk(kind, posSide, trigger, mark) {
  const t = Number(trigger);
  if (!isFinite(t)) return 'Invalid trigger price';
  if (t <= 0) return 'Trigger price must be positive';
  const m = Number(mark);
  if (mark == null || String(mark).trim() === '' || !isFinite(m) || m <= 0) return null;
  const long = String(posSide).toLowerCase() === 'buy';
  if (String(kind).toLowerCase() === 'sl') {
    if (long && t >= m) return 'Stop-loss must be below the mark price for a long';
    if (!long && t <= m) return 'Stop-loss must be above the mark price for a short';
  } else {
    if (long && t <= m) return 'Take-profit must be above the mark price for a long';
    if (!long && t >= m) return 'Take-profit must be below the mark price for a short';
  }
  return null;
}

// ---------------------------------------------------------------------------
// Lighter (venue #12) — PURE helpers, engine-parity (terminal_engine.py).
// Native trading signs via the Go WASM signer (assets/lighter_signer.wasm);
// these helpers are the WASM-independent parts so tests can pin parity under
// plain node without loading the wasm.
// ---------------------------------------------------------------------------
const LIGHTER_HOST = 'mainnet.zklighter.elliot.ai';
const LIGHTER_CHAIN_ID = 304;               // zk mainnet
const LIGHTER_DEFAULT_KEY_INDEX = 2;        // engine LT_DEFAULT_API_KEY_INDEX

// "accountIndex" or "accountIndex:apiKeyIndex" → {acct, kidx} (engine
// lighter_parse_key parity). null on garbage.
function ltParseKey(key) {
  const parts = String(key == null ? '' : key).trim().split(':');
  if (parts.length > 2 || parts[0] === '') return null;
  if (!/^\d+$/.test(parts[0])) return null;
  const acct = Number(parts[0]);
  let kidx = LIGHTER_DEFAULT_KEY_INDEX;
  if (parts.length === 2) {
    if (!/^\d+$/.test(parts[1])) return null;
    kidx = Number(parts[1]);
  }
  if (!Number.isSafeInteger(acct) || acct < 0 ||
      !Number.isInteger(kidx) || kidx < 0 || kidx > 254) return null;
  return { acct: acct, kidx: kidx };
}

// Deterministic 48-bit client_order_index from the panel clOrdID — md5-fold,
// MUST stay byte-identical to engine lighter_coi (cancel resolves and the
// blotter key on it).
function ltCoi(clOrdID) {
  const h = crypto.createHash('md5').update(String(clOrdID == null ? '' : clOrdID)).digest('hex');
  return parseInt(h.slice(0, 12), 16);
}

// Human decimal string → integer venue units (10^decimals), floored.
// String math (no float rounding); null on garbage / negative / unsafe int.
function ltUnits(val, decimals) {
  const s = String(val == null ? '' : val).trim().replace(/^\+/, '');
  if (!/^\d+(\.\d+)?$/.test(s)) return null;
  const d = Number(decimals);
  if (!Number.isInteger(d) || d < 0) return null;
  const dot = s.split('.');
  const frac = ((dot[1] || '') + '0'.repeat(d)).slice(0, d);   // floor
  const out = (dot[0] + frac).replace(/^0+(?=\d)/, '');
  const n = Number(out);
  return Number.isSafeInteger(n) ? n : null;
}

// Market/stop-market execution bound in UNITS: ±2% integer math — equals the
// engine's Decimal ×1.02/×0.98 floor-to-tick on the same unit price.
function ltBoundUnits(pxUnits, buySide) {
  const n = Number(pxUnits);
  if (!Number.isSafeInteger(n) || n <= 0) return null;
  const b = Math.floor(n * (buySide ? 102 : 98) / 100);
  return b > 0 ? b : null;
}

// ===========================================================================
// Multi-venue rollout (Binance, Bybit, OKX, Gate, Bitget — spot + USDT-M
// futures). Same discipline as the Phemex section: everything below is PURE
// (golden-vector parity-tested against terminal_engine.py); the runtime
// wiring further down signs with device-held creds and NEVER falls back to
// the server transport.
// ===========================================================================

const BINANCE_SPOT_HOST = 'api.binance.com';
const BINANCE_FUT_HOST = 'fapi.binance.com';
const BYBIT_HOST = 'api.bybit.com';
const OKX_HOST = 'www.okx.com';
const GATE_HOST = 'api.gateio.ws';
const GATE_API_PREFIX = '/api/v4';     // signature covers the FULL path incl. prefix
const BITGET_HOST = 'api.bitget.com';
const KUCOIN_SPOT_HOST = 'api.kucoin.com';
const KUCOIN_FUT_HOST = 'api-futures.kucoin.com';
const BITMEX_HOST = 'www.bitmex.com';
const BITMEX_API_PREFIX = '/api/v1';   // signature covers the FULL path incl. prefix
const BITGET_PRODUCT_TYPE = 'usdt-futures';
const BINANCE_RECV_WINDOW_MS = 5000;
const BYBIT_RECV_WINDOW_MS = 5000;
const ONEWAY_TTL_MS = 600 * 1000;      // Binance position-mode check cache
const POS_RETRY_DELAY_MS = 400;        // fresh-position REST lag retry

// --- #2026 Binance IP-ban freeze latch (pure) -------------------------------
// Binance EXTENDS an active IP auto-ban for every request received while
// banned (observed live: 51 banned requests in one session kept re-arming
// the ban), so on any 418 — or a 429 that carries a Retry-After / a parsable
// ban body — the shell latches a per-HOST freeze: ZERO requests leave for
// that host until the ban expiry (+ a small pad). The 418 body carries
// "... banned until <epoch-ms> ..."; an unparseable body falls back to a
// fixed backoff that doubles while 418s continue. Spot (api.binance.com)
// shares the mechanism — ban semantics are identical. AsterDex is NOT wired
// in: its observed errors are bare 429s (no body, no Retry-After), already
// handled by the clock-probe backoff.
const BN_BAN_HOSTS = {};
BN_BAN_HOSTS[BINANCE_FUT_HOST] = 1;
BN_BAN_HOSTS[BINANCE_SPOT_HOST] = 1;
const BN_BAN_PAD_MS = 3000;                    // past Binance's own expiry stamp
const BN_BAN_BACKOFF0_MS = 60000;              // unparseable body: fixed backoff…
const BN_BAN_BACKOFF_MAX_MS = 30 * 60 * 1000;  // …doubling while 418s continue

// "banned until 1786464354696" → epoch ms (only when in the future), else null.
function bnBanParseUntil(text, nowMs) {
  const m = /banned\s+until\s+(\d{12,14})/i.exec(String(text || ''));
  if (!m) return null;
  const t = Number(m[1]);
  return (Number.isFinite(t) && t > nowMs) ? t : null;
}

function bnBanTimeTxt(untilMs) {
  const d = new Date(untilMs);
  const p = (n) => String(n).padStart(2, '0');
  return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}

function bnBanMsgFor(st) {
  return 'Binance IP banned — requests frozen until ' + bnBanTimeTxt(st.until)
       + (st.boMs ? ' (backoff — ban expiry unknown)' : '');
}

// Latch transition on ONE observed response for a Binance host.
// reg[host] = { until, boMs }. 418 always latches; 429 latches only when it
// carries a Retry-After hint or a parsable ban body (a plain 429 stays with
// the existing per-caller rate-limit handling). Any sub-400 status clears
// the latch (resets the doubling). Returns the active latch entry, or null
// when cleared / not involved. Pure — the registry object is passed in.
function bnBanRegNote(reg, host, status, text, raSec, nowMs) {
  const s = status | 0;
  const st = reg[host];
  if (s > 0 && s < 400) { if (st) delete reg[host]; return null; }
  if (s !== 418 && s !== 429) return (st && st.until > nowMs) ? st : null;
  const parsed = bnBanParseUntil(text, nowMs);
  const ra = Number(raSec);
  let until, boMs = 0;
  if (parsed) until = parsed + BN_BAN_PAD_MS;
  else if (Number.isFinite(ra) && ra > 0)
    until = nowMs + Math.min(ra * 1000, BN_BAN_BACKOFF_MAX_MS) + BN_BAN_PAD_MS;
  else if (s === 418) {
    // conservative fixed backoff, doubling while unparseable 418s continue
    boMs = Math.min(st && st.boMs ? st.boMs * 2 : BN_BAN_BACKOFF0_MS,
                    BN_BAN_BACKOFF_MAX_MS);
    until = nowMs + boMs;
  } else return (st && st.until > nowMs) ? st : null;   // bare 429: not a ban
  if (st && st.until > until) until = st.until;         // never shorten a ban
  reg[host] = { until: until, boMs: boMs };
  return reg[host];
}

// Freeze gate: the Error to fail a would-be request with while the latch
// holds, else null. An expired latch is KEPT (not deleted) so the doubling
// backoff survives across expiries; only a successful response clears it.
function bnBanGateErr(reg, host, nowMs) {
  if (!BN_BAN_HOSTS[host]) return null;
  const st = reg[host];
  if (!st || st.until <= nowMs) return null;
  const e = new Error(bnBanMsgFor(st));
  e.bnBanUntil = st.until;
  return e;
}

// --- venue time-probe registry (public time endpoints; pure data) ----------
// Every HMAC venue signs with "PC clock + offset" where offset comes from a
// lazy TTL-refreshed probe of that venue's public time endpoint (same
// discipline as the original Phemex timeSync: stamp-first single probe per
// TTL, failure keeps the last offset, initial 0 = raw PC clock). Offset 0
// keeps every signature byte-identical to before (golden parity).
// BitMEX has NO public time endpoint — it reads the HTTP Date header off a
// cheap unauthenticated GET instead (second resolution; centered +500ms —
// plenty for a 30s api-expires window).
const VENUE_TIME_PROBES = {
  'phemex': { host: PHEMEX_HOST, path: '/public/time',
              ext: (d) => Number((d && d.data && (d.data.serverTime || d.data.timestamp))) },
  'binance:spot':    { host: BINANCE_SPOT_HOST, path: '/api/v3/time',
                       ext: (d) => Number((d || {}).serverTime) },
  'binance:futures': { host: BINANCE_FUT_HOST, path: '/fapi/v1/time',
                       ext: (d) => Number((d || {}).serverTime) },
  'bybit':  { host: BYBIT_HOST, path: '/v5/market/time',
              ext: (d) => Number((((d || {}).result) || {}).timeNano) / 1e6 },
  'okx':    { host: OKX_HOST, path: '/api/v5/public/time',
              ext: (d) => Number(((((d || {}).data) || [])[0] || {}).ts) },
  'gate':   { host: GATE_HOST, path: GATE_API_PREFIX + '/spot/time',
              ext: (d) => Number((d || {}).server_time) },
  'bitget': { host: BITGET_HOST, path: '/api/v2/public/time',
              ext: (d) => Number(((d || {}).data || {}).serverTime) },
  'kucoin:spot':    { host: KUCOIN_SPOT_HOST, path: '/api/v1/timestamp',
                      ext: (d) => Number((d || {}).data) },
  'kucoin:futures': { host: KUCOIN_FUT_HOST, path: '/api/v1/timestamp',
                      ext: (d) => Number((d || {}).data) },
  'bitmex': { host: BITMEX_HOST, path: BITMEX_API_PREFIX + '/announcement/urgent',
              dateHeader: true },
  'asterdex:futures': { host: ASTER_FUT_HOST, path: '/fapi/v1/time',
                        ext: (d) => Number((d || {}).serverTime) },
  'asterdex:spot':    { host: ASTER_SPOT_HOST, path: '/api/v1/time',
                        ext: (d) => Number((d || {}).serverTime) },
  'mexc:spot':    { host: 'api.mexc.com', path: '/api/v3/time',
                    ext: (d) => Number((d || {}).serverTime) },
  'mexc:futures': { host: 'contract.mexc.com', path: '/api/v1/contract/ping',
                    ext: (d) => Number((d || {}).data) },
  // Lighter status lives at the host ROOT '/' (SDK root_api resource_path;
  // /api/v1/status does NOT exist — CloudFront 403s it). Its `timestamp` is
  // whole SECONDS (verified live 2026-07-29) → ×1000 and center by +500ms
  // (BitMEX dateHeader convention) — plenty for signer expiry stamps.
  'lighter': { host: 'mainnet.zklighter.elliot.ai', path: '/',
               ext: (d) => Number((d || {}).timestamp) * 1000 + 500 },
  // Kraken spot Time is whole SECONDS (×1000, centered +500ms); futures has
  // no public time endpoint but every REST envelope stamps an ISO serverTime.
  'kraken:spot':    { host: 'api.kraken.com', path: '/0/public/Time',
                      ext: (d) => Number((((d || {}).result) || {}).unixtime) * 1000 + 500 },
  'kraken:futures': { host: 'futures.kraken.com', path: '/derivatives/api/v3/tickers/PF_XBTUSD',
                      ext: (d) => Date.parse((d || {}).serverTime) },
};

// venue+market → probe spec (market-split hosts get their own offsets).
function venueTimeProbe(venue, market) {
  const mk = market === 'spot' ? 'spot' : 'futures';
  return VENUE_TIME_PROBES[venue + ':' + mk] || VENUE_TIME_PROBES[venue] || null;
}
function venueTimeProbeKey(venue, market) {
  const mk = market === 'spot' ? 'spot' : 'futures';
  return VENUE_TIME_PROBES[venue + ':' + mk] ? venue + ':' + mk
       : (VENUE_TIME_PROBES[venue] ? venue : null);
}

// serverMs vs midpoint of the probe round-trip → offset to ADD to Date.now().
function venueClkOffset(serverMs, t0, t1) {
  return Number(serverMs) - (Number(t0) + Number(t1)) / 2;
}

// #2012 clock-probe 429 backoff (Aster field test: 113 probes, 54× 429 —
// force=true warm-up bursts kept hammering a rate-limited /time endpoint
// every ~60s). On a 429 the probe backs off exponentially (≥5 min, capped
// 60 min) and signed calls REUSE the last known offset — venue clocks drift
// slowly, a stale offset beats hammering. Any successful probe resets the
// ladder. Pure (node-tested); no behavior change for venues that never 429.
const CLK_BO_BASE_MS = 5 * 60 * 1000;
const CLK_BO_MAX_MS = 60 * 60 * 1000;
function clkProbe429(st, now) {
  st.boN = Math.min((st.boN | 0) + 1, 6);
  st.boUntil = now + Math.min(CLK_BO_MAX_MS, CLK_BO_BASE_MS * Math.pow(2, st.boN - 1));
  return st.boUntil - now;
}
function clkProbeOk(st) { st.boN = 0; st.boUntil = 0; }
function clkProbeBlocked(st, now) { return now < ((st && st.boUntil) || 0); }

// #2192 probe hygiene — a slow round-trip poisons the midpoint math: the
// error can reach ~rtt/2 when the delay is one-sided (field 2026-08-14: a
// 5082ms cold-proxy-tunnel boot probe latched binance:spot offset +2622ms,
// true ~+150ms → every spot-signed call -1021 for the whole session).
// Never latch a sample whose rtt exceeds CLK_RTT_SANE_MS: re-sample on the
// now-warm socket (bounded by tries AND wall budget), keep the min-rtt
// sample, and when EVERY sample is slow keep the last offset and retry
// after CLK_SLOW_RETRY_MS instead of waiting out the 10-min TTL. Pure.
const CLK_RTT_SANE_MS = 1500;
const CLK_PROBE_TRIES = 3;
const CLK_SLOW_RETRY_MS = 30 * 1000;
const CLK_PROBE_BUDGET_MS = 8000;
function clkProbeFold(samples) {
  let best = null;
  for (const s of (samples || [])) {
    const rtt = Number((s || {}).t1) - Number((s || {}).t0);
    const sv = Number((s || {}).sv);
    if (!isFinite(rtt) || rtt < 0 || !isFinite(sv) || sv <= 1e12) continue;
    if (!best || rtt < best.rtt) best = { rtt: rtt, off: venueClkOffset(sv, s.t0, s.t1) };
  }
  if (!best) return { accept: false, offsetMs: null, rtt: null };
  return { accept: best.rtt <= CLK_RTT_SANE_MS, offsetMs: best.off, rtt: best.rtt };
}
// #2192 timestamp-rejection classifier (-1021 class): numeric Binance code
// or the message text — the ws-api subscribe error surfaces TEXT only
// ("spot subscribe failed: Timestamp for this request was 1000ms ahead…").
function clkTsReject(code, msg) {
  if (Number(code) === -1021) return true;
  return /ahead of the server|outside of the recv ?window/i.test(String(msg || ''));
}

// Offset-corrected timestamp stampers (offset 0 → byte-identical to the old
// raw Date.now() stamps — Date.now() is already an integer).
function venueStampMs(offsetMs, nowMs) {
  return String(Math.round((nowMs != null ? Number(nowMs) : Date.now()) + (offsetMs || 0)));
}
function venueStampSec(offsetMs, nowMs) {
  return String(Math.floor(((nowMs != null ? Number(nowMs) : Date.now()) + (offsetMs || 0)) / 1000));
}

// --- exact decimal helpers (BigInt — Python Decimal parity) ----------------
// Parse a plain decimal string → { neg, digits(BigInt, unsigned), scale }.
function decNorm(v) {
  const s = String(v).trim();
  const m = /^([+-]?)(\d+)(?:\.(\d+))?$/.exec(s);
  if (!m) throw new Error('bad decimal: ' + s);
  const neg = m[1] === '-';
  const frac = m[3] || '';
  return { neg: neg, digits: BigInt(m[2] + frac), scale: frac.length };
}

// Decimal(v).normalize() formatted 'f' — parity with terminal_engine.bn_num
// for plain decimal strings ('0.01000000' → '0.01'); null when unparseable.
function bnNum(v) {
  if (v == null) return null;
  let d;
  try { d = decNorm(v); } catch (e) { return null; }
  return decFmt(d.neg, d.digits, d.scale);
}

// (neg, digits BigInt, scale) → trimmed decimal string — _hist_fmt parity.
function decFmt(neg, digits, scale) {
  if (digits === 0n) return '0';
  let s = digits.toString();
  let sc = scale;
  while (sc > 0 && s.endsWith('0')) { s = s.slice(0, -1); sc -= 1; }
  if (s.length <= sc) s = '0'.repeat(sc - s.length + 1) + s;
  const out = sc > 0 ? s.slice(0, -sc) + '.' + s.slice(-sc) : s;
  return (neg ? '-' : '') + out;
}

// num/den → BigInt quotient rounded HALF-EVEN (Python Decimal.quantize default).
function divHalfEven(num, den) {
  let q = num / den;
  const rem = num % den;
  const twice = rem * 2n;
  if (twice > den || (twice === den && q % 2n === 1n)) q += 1n;
  return q;
}

// --- Binance pure builders (parity with terminal_engine.py) ----------------
function binanceSign(secret, query) {
  return crypto.createHmac('sha256', String(secret)).update(String(query), 'utf8').digest('hex');
}

const BINANCE_ERRORS = {
  '-1003': 'Rate limited by Binance — retry shortly',
  '-1013': 'Order rejected by a symbol filter (price/qty/notional)',
  '-1021': 'Request timestamp outside recvWindow — server clock skew',
  '-1022': 'Invalid request signature — re-enter your API keys',
  '-1102': 'Mandatory parameter missing or malformed',
  '-1111': 'Precision over the maximum defined for this asset',
  '-1121': 'Invalid symbol',
  '-2010': 'Order rejected — insufficient balance or invalid parameters',
  '-2011': 'Order already cancelled or filled',
  '-2013': 'Order does not exist',
  '-2014': 'Invalid API key format',
  '-2015': 'Invalid API key, IP whitelist, or permissions',
  '-2018': 'Balance is insufficient',
  '-2019': 'Margin is insufficient',
  '-2022': 'Reduce-only order is rejected',
  '-4028': 'Invalid leverage value',
  '-4046': 'No need to change margin type',
  '-4061': 'Order side does not match the position mode — one-way required',
  '-4120': 'Conditional orders must use the Algo Order API — engine out of date (this should never surface; report it)',
};

function binanceErrorMessage(code, rawMsg) {
  const key = String(parseInt(code, 10));
  const msg = key !== 'NaN' ? BINANCE_ERRORS[key] : undefined;
  if (msg) return msg;
  const tail = rawMsg ? ': ' + rawMsg : '';
  return 'Binance error ' + code + tail;
}

const BN_TYPE_MAP = { market: 'MARKET', limit: 'LIMIT', stop: 'STOP_MARKET',
                      stop_limit: 'STOP', tp_market: 'TAKE_PROFIT_MARKET' };
const BN_ALGO_TYPES = ['STOP', 'STOP_MARKET', 'TAKE_PROFIT',
                       'TAKE_PROFIT_MARKET', 'TRAILING_STOP_MARKET'];

function binanceAlgoOrderParams(symbol, side, ordType, qty, price, clOrdID, flags) {
  const f = flags || {};
  const sideU = String(side).toLowerCase() === 'buy' ? 'BUY' : 'SELL';
  const typ = BN_TYPE_MAP[String(ordType).toLowerCase()] || 'STOP_MARKET';
  const params = [['symbol', String(symbol)], ['side', sideU], ['type', typ],
                  ['algoType', 'CONDITIONAL']];
  if (typ === 'STOP') {
    params.push(['timeInForce', 'GTC']);
    params.push(['quantity', String(qty)]);
    params.push(['price', String(price)]);
  } else if (f.closePosition) {
    params.push(['closePosition', 'true']);
  } else {
    params.push(['quantity', String(qty)]);
  }
  params.push(['triggerPrice', String(f.trigger)]);
  if (f.reduceOnly && !f.closePosition) params.push(['reduceOnly', 'true']);
  params.push(['clientAlgoId', String(clOrdID)]);
  return params;
}

function binanceOrderParams(market, symbol, side, ordType, qty, price, clOrdID, flags) {
  const f = flags || {};
  const sideU = String(side).toLowerCase() === 'buy' ? 'BUY' : 'SELL';
  const typ = BN_TYPE_MAP[String(ordType).toLowerCase()] || 'LIMIT';
  const params = [['symbol', String(symbol)], ['side', sideU], ['type', typ]];
  if (typ === 'LIMIT' || typ === 'STOP') {
    params.push(['timeInForce', 'GTC']);
    params.push(['quantity', String(qty)]);
    params.push(['price', String(price)]);
  } else if (typ === 'MARKET') {
    if (market === 'spot' && sideU === 'BUY') {
      params.push(['quoteOrderQty', String(qty)]);
    } else {
      params.push(['quantity', String(qty)]);
    }
  } else {
    if (f.closePosition) {
      params.push(['closePosition', 'true']);
    } else {
      params.push(['quantity', String(qty)]);
    }
  }
  if (typ === 'STOP' || typ === 'STOP_MARKET' || typ === 'TAKE_PROFIT_MARKET') {
    params.push(['stopPrice', String(f.trigger)]);
  }
  if (market === 'futures' && f.reduceOnly && !f.closePosition) {
    params.push(['reduceOnly', 'true']);
  }
  params.push(['newClientOrderId', String(clOrdID)]);
  return params;
}

// /fapi/v2/positionRisk rows → common position rows (engine parity).
function binancePositionRows(data) {
  const rows = [];
  for (const p of Array.isArray(data) ? data : []) {
    try {
      const amt = bnNum(p.positionAmt) || '0';
      if (Number(amt) === 0) continue;
      const neg = amt.startsWith('-');
      rows.push({
        symbol: p.symbol,
        side: neg ? 'Sell' : 'Buy',
        size: neg ? amt.slice(1) : amt,
        mark: bnNum(p.markPrice),
      });
    } catch (e) { /* skip bad row */ }
  }
  return rows;
}

// --- #1943 Binance shell user-data streams (pure helpers) -------------------
// Kraken-grade instant display for native Binance: the shell keeps private
// user-data WS sessions per armed slot and pushes ledger mutations to every
// panel window through the same att:ledger-push channel (venue-tagged
// 'binance'; Kraken frames stay byte-identical — krPushDrain's venue arg
// defaults 'kraken').
//   Spot: the legacy listenKey REST plumbing was REMOVED by Binance
//   2026-02-20 (HTTP 410). Private events ride the ws-api connection —
//   send a userDataStream.subscribe.signature frame (params {apiKey,
//   recvWindow, timestamp} sorted+urlencoded, HMAC-SHA256 hex; the
//   signature excluded from the signed payload). Events arrive WRAPPED
//   ({subscriptionId, event:{...}}); expiry is in-band eventStreamTerminated.
//   Futures: listenKey REST (POST/PUT /fapi/v1/listenKey — API-key header
//   only, unsigned) is unchanged, but private events since 2026-04-23 push
//   only on the routed /private/ws/<listenKey> path (the plain /ws/<lk>
//   connects but stays silent). Same facts the server engine path learned.
const BN_SPOT_WSAPI_URL = 'wss://ws-api.binance.com:443/ws-api/v3';
const BN_FUT_WS_BASE = 'wss://fstream.binance.com/private/ws/';
const BN_LK_KEEPALIVE_MS = 30 * 60 * 1000;   // Binance listenKey expiry: 60 min
// User-data streams carry no ~1s heartbeat (Binance pings every ~3 min) —
// the live window must be generous or a quiet account flaps stale.
const BN_UDS_STALE_MS = 10 * 60 * 1000;
const BN_UDS_FILLS_CAP = 400;

// ws-api signature-subscribe frame (engine twin: spot_subscribe_frame).
// MUST be built immediately before the ws send (fresh timestamp each
// (re)connect). Pure — node-testable with a fixed nowMs.
function bnSpotSubscribeFrame(apiKey, secret, nowMs, reqId) {
  const params = [['apiKey', String(apiKey)],
                  ['recvWindow', String(BINANCE_RECV_WINDOW_MS)],
                  ['timestamp', String(nowMs)]];
  params.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const payload = params.map((p) =>
    encodeURIComponent(p[0]) + '=' + encodeURIComponent(p[1])).join('&');
  return { id: String(reqId || ('bnsub' + nowMs)),
           method: 'userDataStream.subscribe.signature',
           params: { apiKey: String(apiKey),
                     recvWindow: BINANCE_RECV_WINDOW_MS,
                     timestamp: Number(nowMs),
                     signature: binanceSign(secret, payload) } };
}

// Normalize one ws-api / user-stream frame to the bare event dict (engine
// twin: bn_ws_event). Spot ws-api wraps events as {subscriptionId, event};
// futures /private/ws pushes bare {e:...}. Request responses ({id, status})
// and anything without an event type return null.
function bnWsEvent(msg) {
  if (!msg || typeof msg !== 'object') return null;
  const ev = msg.event;
  if (ev && typeof ev === 'object' && ev.e) return ev;
  if (msg.e) return msg;
  return null;
}

// Order lifecycle classification for executionReport / ORDER_TRADE_UPDATE
// status X. 'add' keeps/creates the ledger row, 'gone' removes it (push
// 'ordgone'), null = no order-state mutation (calculated/unknown states).
function bnOrdEffect(X) {
  const s = String(X || '');
  if (s === 'NEW' || s === 'PARTIALLY_FILLED') return 'add';
  if (s === 'FILLED' || s === 'CANCELED' || s === 'EXPIRED' ||
      s === 'REJECTED' || s === 'EXPIRED_IN_MATCH') return 'gone';
  return null;
}

// Exactly-once fill ingest at the shell boundary: one seen-map per scope
// keyed by the venue trade id namespace ('s:<t>' spot / 'f:<t>' futures) —
// a WS redelivery (reconnect replay) can never double-apply. Returns the
// fid when the row is NEW (caller records + pushes), null when seen.
function bnFillIngest(fills, prefix, tradeId) {
  if (!fills || tradeId == null || tradeId === '') return null;
  const fid = prefix + ':' + String(tradeId);
  if (fills.seen[fid]) return null;
  fills.seen[fid] = 1;
  if (Object.keys(fills.seen).length > 4000) {
    // bounded: keep the ids of the retained rows only
    const keep = {};
    for (const r of fills.rows) if (r && r._fid) keep[r._fid] = 1;
    keep[fid] = 1;
    fills.seen = keep;
  }
  return fid;
}

// --- #1969 device-local blotter (pure) --------------------------------------
// Local "Your trades" store for NATIVE-armed venues: the shell keeps a
// persistent per-scope fills archive on the device and the panel renders the
// blotter from it — the server participates in NOTHING during trading.
// The functions below are PURE twins of the engine's normalizers
// (norm_kr_ws_spot_trade / norm_kr_ws_fut_fill / norm_bn_fut_fill /
// norm_bn_spot_fill) and of reconstruct_trades — parity is test-guarded
// (tests/test_local_blotter.py golden sets). Same schema, same exec-id
// space, so an explicit "Save to server" ingests without duplicate legs.
function lbNum(v) {
  // bn_num twin: venue decimal string → trimmed decimal string; null when
  // unparseable. Lexical trim (no float round-trip) for plain decimals.
  if (v == null) return null;
  let s = String(v).trim();
  if (!/^[+-]?(\d+)(\.\d+)?([eE][+-]?\d+)?$/.test(s)) return null;
  if (/[eE]/.test(s)) {
    const n = Number(s);
    if (!Number.isFinite(n)) return null;
    return lbFmt(n);
  }
  let neg = false;
  if (s[0] === '+') s = s.slice(1);
  if (s[0] === '-') { neg = true; s = s.slice(1); }
  if (s.indexOf('.') >= 0) s = s.replace(/0+$/, '').replace(/\.$/, '');
  s = s.replace(/^0+(?=\d)/, '');
  if (s === '' || s === '0') return '0';
  return (neg ? '-' : '') + s;
}
function lbFmt(n) {
  // _hist_fmt twin for COMPUTED values: ~12 significant digits, trailing
  // zeros trimmed, '0' for zero/non-finite. Plain notation (no exponent).
  n = Number(n);
  if (!Number.isFinite(n) || n === 0) return '0';
  const mag = Math.floor(Math.log10(Math.abs(n)));
  const dec = Math.min(20, Math.max(0, 12 - mag));
  let s = n.toFixed(dec);
  if (s.indexOf('.') >= 0) s = s.replace(/0+$/, '').replace(/\.$/, '');
  return s === '-0' ? '0' : s;
}
function lbMoney(n) {
  // _hist_money twin: money/percent aggregate → 8-dp-rounded number.
  n = Number(n);
  if (!Number.isFinite(n)) return 0;
  return Math.round(n * 1e8) / 1e8;
}
function lbKrAsset(a) {
  // kr_asset_norm twin.
  let s = String(a || '');
  if (s.length === 4 && (s[0] === 'X' || s[0] === 'Z')) s = s.slice(1);
  s = s.split('.')[0];
  return { XBT: 'BTC', XDG: 'DOGE' }[s] || s;
}
function lbKrFeeAlt(amt, asset) {
  // kr_fee_alt_str twin: '0.0000041 BTC'.
  const a = lbNum(amt) || '0';
  return (a + ' ' + lbKrAsset(String(asset || '').toUpperCase())).trim();
}
function lbIsoMs(v) {
  // kr_iso_ms twin: ISO timestamp → epoch ms (0 on failure).
  const t = v ? Date.parse(String(v)) : NaN;
  return Number.isFinite(t) ? t : 0;
}
// One kraken spot WS-v2 executions element (exec_type 'trade') → the
// reconstruct_trades fill schema. Twin of norm_kr_ws_spot_trade (no
// fee_map on the device — WS rows carry their own fees list).
function lbNormKrWsSpot(e) {
  if (!e || typeof e !== 'object') return null;
  if (String(e.exec_type || '') !== 'trade') return null;
  const sym = String(e.symbol || '');
  const sz = lbNum(e.last_qty);
  if (!sym || sz == null || !(Number(sz) > 0)) return null;
  let px = lbNum(e.last_price) || '0';
  const cost = lbNum(e.cost);
  if (!(Number(px) > 0) && cost && Number(cost) > 0 && Number(sz) > 0) {
    px = lbFmt(Number(cost) / Number(sz));
  }
  const quote = sym.indexOf('/') >= 0
    ? lbKrAsset(sym.split('/').pop().toUpperCase()) : '';
  let fee = 0, alt = null;
  for (const f of (Array.isArray(e.fees) ? e.fees : [])) {
    if (!f || typeof f !== 'object') continue;
    const q = lbNum(f.qty);
    if (q == null) continue;
    const asset = lbKrAsset(String(f.asset || '').toUpperCase());
    if (asset && asset === quote) fee += Number(q);
    else if (alt === null) alt = lbKrFeeAlt(q, asset);
  }
  const out = {
    venue: 'kraken', market: 'spot', symbol: sym,
    side: String(e.side || '').toLowerCase(), posSide: '',
    order_px: '', exec_px: px, qty: sz,
    value: lbNum(e.cost) || lbFmt(Number(sz) * Number(px)),
    fee: fee ? lbFmt(fee) : '0', closed_pnl: '0',
    exec_id: String(e.exec_id || e.trade_id || ''),
    order_id: String(e.order_id || ''),
    ts: lbIsoMs(e.timestamp), type: 'Trade',
  };
  if (alt) out.fee_alt = alt;
  return out;
}
// One kraken futures ws/v1 fills row → the fill schema. Twin of
// norm_kr_ws_fut_fill without the Account-Log fee_map join (device-only:
// fee_paid when the WS carries it, honest '0' otherwise).
function lbNormKrWsFut(f) {
  if (!f || typeof f !== 'object') return null;
  const sym = String(f.instrument || '').toUpperCase();
  const sz = lbNum(f.qty);
  if (!sym || sz == null || !(Number(sz) > 0)) return null;
  const px = lbNum(f.price) || '0';
  const ts = lbIsoMs(f.time) || (Number(f.time) > 0 ? Number(f.time) : 0);
  let fee = '0', alt = null;
  const fp = lbNum(f.fee_paid);
  if (fp != null && Number(fp) !== 0) {
    const cur = lbKrAsset(String(f.fee_currency || 'USD').toUpperCase());
    if (cur === '' || cur === 'USD' || cur === 'USDT' || cur === 'USDC') fee = fp;
    else alt = lbKrFeeAlt(fp, cur);
  }
  const out = {
    venue: 'kraken', market: 'futures', symbol: sym,
    side: (f.buy === true || f.buy === 'true' || f.buy === 1) ? 'buy' : 'sell',
    posSide: '', order_px: '', exec_px: px, qty: sz,
    value: lbFmt(Number(sz) * Number(px)),
    fee: fee, closed_pnl: '0',
    exec_id: String(f.fill_id || ''),
    order_id: String(f.order_id || ''),
    ts: ts,
    type: String(f.fill_type || '').toLowerCase() === 'liquidation'
      ? 'Liquidation' : 'Trade',
  };
  if (alt) out.fee_alt = alt;
  return out;
}
// One Binance futures ORDER_TRADE_UPDATE `o` payload (x==TRADE) → the fill
// schema. Twin of norm_bn_fut_fill.
function lbNormBnFut(o, evTs) {
  if (!o || typeof o !== 'object') return null;
  const qty = lbNum(o.l) || '0';
  if (!(Number(qty) > 0)) return null;
  const sym = String(o.s || '');
  if (!sym) return null;
  const px = lbNum(o.L) || '0';
  const feeAsset = String(o.N || '');
  const fee = (feeAsset === 'USDT' || feeAsset === 'USDC' || feeAsset === 'BUSD'
               || feeAsset === 'FDUSD' || feeAsset === '')
    ? (lbNum(o.n) || '0') : '0';
  return {
    venue: 'binance', market: 'futures', symbol: sym,
    side: String(o.S || '').toUpperCase() === 'BUY' ? 'buy' : 'sell',
    posSide: '', order_px: lbNum(o.p) || '', exec_px: px, qty: qty,
    value: lbFmt(Number(px) * Number(qty)),
    fee: fee, closed_pnl: lbNum(o.rp) || '0',
    kind: 'trade', funding: '0',
    ts: Math.floor(Number(o.T) || Number(evTs) || 0),
    exec_id: String(o.t != null ? o.t : ''),
  };
}
// One Binance spot executionReport (x==TRADE) → the fill schema. Twin of
// norm_bn_spot_fill (base-asset fee ×price, quote as-is, BNB → 0).
function lbNormBnSpot(m) {
  if (!m || typeof m !== 'object') return null;
  const qty = lbNum(m.l) || '0';
  if (!(Number(qty) > 0)) return null;
  const sym = String(m.s || '');
  if (!sym) return null;
  const px = lbNum(m.L) || '0';
  const feeRaw = lbNum(m.n) || '0';
  const feeAsset = String(m.N || '');
  let fee;
  if (feeAsset && sym.indexOf(feeAsset) === 0 && sym.slice(-feeAsset.length) !== feeAsset) {
    fee = lbFmt(Number(feeRaw) * Number(px));
  } else if (feeAsset && sym.slice(-feeAsset.length) === feeAsset) {
    fee = feeRaw;
  } else if (!feeAsset) {
    fee = feeRaw;
  } else {
    fee = '0';
  }
  const val = lbNum(m.Y) || lbFmt(Number(px) * Number(qty));
  return {
    venue: 'binance', market: 'spot', symbol: sym,
    side: String(m.S || '').toUpperCase() === 'BUY' ? 'buy' : 'sell',
    posSide: '', order_px: lbNum(m.p) || '', exec_px: px, qty: qty,
    value: val, fee: fee, closed_pnl: '0',
    kind: 'trade', funding: '0',
    ts: Math.floor(Number(m.T) || Number(m.E) || 0),
    exec_id: String(m.t != null ? m.t : ''),
  };
}
// Binance REST backfill rows — /fapi/v1/userTrades and /api/v3/myTrades.
// SAME exec-id space as the WS twins (REST `id` == WS `t` trade id), so
// the startup backfill dedupes against live-recorded copies to a no-op.
function lbNormBnFutRest(r) {
  if (!r || typeof r !== 'object') return null;
  const qty = lbNum(r.qty) || '0';
  if (!(Number(qty) > 0)) return null;
  const sym = String(r.symbol || '');
  if (!sym) return null;
  const px = lbNum(r.price) || '0';
  const feeAsset = String(r.commissionAsset || '');
  const fee = (feeAsset === 'USDT' || feeAsset === 'USDC' || feeAsset === 'BUSD'
               || feeAsset === 'FDUSD' || feeAsset === '')
    ? (lbNum(r.commission) || '0') : '0';
  return {
    venue: 'binance', market: 'futures', symbol: sym,
    side: String(r.side || '').toUpperCase() === 'BUY' ? 'buy' : 'sell',
    posSide: '', order_px: '', exec_px: px, qty: qty,
    value: lbNum(r.quoteQty) || lbFmt(Number(px) * Number(qty)),
    fee: fee, closed_pnl: lbNum(r.realizedPnl) || '0',
    kind: 'trade', funding: '0',
    ts: Math.floor(Number(r.time) || 0),
    exec_id: String(r.id != null ? r.id : ''),
  };
}
function lbNormBnSpotRest(r) {
  if (!r || typeof r !== 'object') return null;
  const qty = lbNum(r.qty) || '0';
  if (!(Number(qty) > 0)) return null;
  const sym = String(r.symbol || '');
  if (!sym) return null;
  const px = lbNum(r.price) || '0';
  const feeRaw = lbNum(r.commission) || '0';
  const feeAsset = String(r.commissionAsset || '');
  let fee;
  if (feeAsset && sym.indexOf(feeAsset) === 0 && sym.slice(-feeAsset.length) !== feeAsset) {
    fee = lbFmt(Number(feeRaw) * Number(px));
  } else if (feeAsset && sym.slice(-feeAsset.length) === feeAsset) {
    fee = feeRaw;
  } else if (!feeAsset) {
    fee = feeRaw;
  } else {
    fee = '0';
  }
  return {
    venue: 'binance', market: 'spot', symbol: sym,
    side: r.isBuyer === true ? 'buy' : 'sell',
    posSide: '', order_px: '', exec_px: px, qty: qty,
    value: lbNum(r.quoteQty) || lbFmt(Number(px) * Number(qty)),
    fee: fee, closed_pnl: '0',
    kind: 'trade', funding: '0',
    ts: Math.floor(Number(r.time) || 0),
    exec_id: String(r.id != null ? r.id : ''),
  };
}
// #2051 One Bybit V5 execution row (WS `execution` topic and REST
// /v5/execution/list share field names) → the fill schema. Twin of the
// engine's norm_byb_fill: only execType=="Trade" rows normalize; linear
// execFee is USDT (cost-positive, as-is); spot fees are charged in the
// RECEIVED currency — feeCurrency (or the side when absent) decides
// base (×price) vs quote (as-is). execPnl (per-fill realized PnL on newer
// UTA accounts) maps to closed_pnl when carried.
function lbNormBybFill(f) {
  if (!f || typeof f !== 'object') return null;
  if (String(f.execType || 'Trade') !== 'Trade') return null;
  const qty = lbNum(f.execQty) || '0';
  if (!(Number(qty) > 0)) return null;
  const sym = String(f.symbol || '');
  if (!sym) return null;
  const market = String(f.category || 'linear') === 'spot' ? 'spot' : 'futures';
  const px = lbNum(f.execPrice) || '0';
  const side = String(f.side || '').toLowerCase() === 'buy' ? 'buy' : 'sell';
  const feeRaw = lbNum(f.execFee) || '0';
  let fee = feeRaw;
  if (market === 'spot') {
    const fc = String(f.feeCurrency || '');
    const baseFee = fc ? (sym.indexOf(fc) === 0 && sym.slice(-fc.length) !== fc)
                       : side === 'buy';
    if (baseFee) fee = lbFmt(Number(feeRaw) * Number(px));
  }
  return {
    venue: 'bybit', market: market, symbol: sym,
    side: side, posSide: '',
    order_px: lbNum(f.orderPrice) || '', exec_px: px, qty: qty,
    value: lbNum(f.execValue) || lbFmt(Number(px) * Number(qty)),
    fee: fee, closed_pnl: lbNum(f.execPnl) || '0',
    kind: 'trade', funding: '0',
    ts: Math.floor(Number(f.execTime) || 0),
    exec_id: String(f.execId || ''),
  };
}
// #2153 gate fill → normalized blotter row. Engine norm_gate_fill twin —
// the exec-id space (String(f.id)) and every field rule must stay
// byte-identical to the engine's so local/server dedup keys agree.
// Futures rows size in SIGNED CONTRACTS (sign = side; ×quanto_multiplier →
// base qty; mult unknown ⇒ null — the raw row stays cached and the next
// drain re-normalizes once the contract map warmed). Spot fee is charged
// in the RECEIVED currency: base-ccy fee ×price, quote as-is, other (GT
// deduction) ⇒ 0. Gate hands NO per-fill closed PnL — '0' always (NET
// comes from local-blotter replay panel-side).
// #2237 ts rides lbGateTsMs: Gate ships BOTH units under `create_time_ms`
// (spot = ms string, futures = seconds double — verified live on the public
// tape 2026-08-15), so the field name proves nothing and only MAGNITUDE
// does. Same fold as the engine's `>10**12 ? v : v*1000` order-row twin; a
// seconds ts here would date persisted blotter rows to 1970.
function lbGateTsMs(v) {
  if (v == null) return 0;
  const n = Number(v);
  if (!Number.isFinite(n) || !(n > 0)) return 0;
  return Math.floor(n > 1e12 ? n : n * 1000);
}
// #2177 gate hedge-mode position side from a futures fill's `close_size`
// (my_trades_timerange / re-import rows carry it; WS usertrades rows do
// NOT → '' = unknown, replay degrades to legacy one-way netting). Gate
// semantics: close_size shares the size sign; 0 = opening (side sign IS
// the position side), <0 closes a LONG, >0 closes a SHORT. A one-way flip
// row (|size| > |close_size|, close_size ≠ 0) spans BOTH sides → '' —
// dual mode never produces flips, so ambiguity only exists where legacy
// netting is correct anyway.
function lbGatePsd(sz, csRaw) {
  if (csRaw == null || csRaw === '') return '';
  const cs = Number(csRaw);
  if (!Number.isFinite(cs)) return '';
  if (cs === 0) return sz > 0 ? 'long' : 'short';
  if (cs < 0 && sz < 0) return sz >= cs ? 'long' : '';
  if (cs > 0 && sz > 0) return sz <= cs ? 'short' : '';
  return '';
}
// #2177 dual-mode split gate: {long:[],short:[]} iff EVERY trade row in the
// group carries a derived posSide AND both sides appear — else null (legacy
// one-way replay stays byte-identical: old rows, WS-only rows and flip rows
// all lack posSide, and a single-sided group replays the same either way).
// Venues whose FUTURES rows can carry a per-position side (hedge mode).
// gate (#2177) tags posSide from close_size; bitget (#2251) from the
// documented tradeSide/posSide enum. Every other venue writes posSide ''
// on every row, so lbGateDualSplit returns null there anyway — the gate
// keeps the hot replay path from scanning rows it can never split.
function lbDualVenue(r) {
  if (!r || r.market !== 'futures') return false;
  return r.venue === 'gate' || r.venue === 'bitget';
}
function lbGateDualSplit(tradeRows) {
  let hasL = false, hasS = false;
  for (const r of (tradeRows || [])) {
    const p = r.posSide;
    if (p === 'long') hasL = true;
    else if (p === 'short') hasS = true;
    else return null;
  }
  if (!hasL || !hasS) return null;
  return { long: tradeRows.filter((r) => r.posSide === 'long'),
           short: tradeRows.filter((r) => r.posSide === 'short') };
}
function lbNormGateFill(f, market, mult) {
  if (!f || typeof f !== 'object') return null;
  // #2167: /futures/usdt/my_trades_timerange rows carry `trade_id` — NOT
  // `id` (MyFuturesTradeTimeRange model). The id-only read silently nulled
  // EVERY backfill/re-import futures fill (mult>0 so the multMiss guard
  // never fired → hwmFut stayed 0 forever). WS usertrades + /spot/my_trades
  // + plain /futures my_trades keep `id`; both name the same venue trade-id
  // space, so dedup keys stay consistent across lanes.
  const eid = f.id != null ? String(f.id)
    : (f.trade_id != null ? String(f.trade_id) : '');
  if (!eid) return null;
  const px = lbNum(f.price) || '0';
  if (!(Number(px) > 0)) return null;
  const ts = lbGateTsMs(f.create_time_ms != null ? f.create_time_ms
                                                 : f.create_time);
  let row = null;
  if (market === 'futures') {
    const sz = Number(f.size);
    if (!Number.isFinite(sz) || sz === 0) return null;
    const m = Number(mult);
    if (!(m > 0)) return null;   // contract map cold — re-normalized next drain
    const qty = lbFmt(Math.abs(sz) * m);
    if (!(Number(qty) > 0)) return null;
    const fee = (Number(f.fee) || 0) + (Number(f.point_fee) || 0);
    row = {
      venue: 'gate', market: 'futures', symbol: String(f.contract || ''),
      side: sz > 0 ? 'buy' : 'sell', posSide: lbGatePsd(sz, f.close_size),
      order_px: '', exec_px: px, qty: qty,
      value: lbFmt(Number(px) * Number(qty)),
      fee: lbFmt(fee), closed_pnl: '0',
      kind: 'trade', funding: '0', ts: ts, exec_id: eid,
    };
  } else {
    const qty = lbNum(f.amount) || '0';
    if (!(Number(qty) > 0)) return null;
    const pair = String(f.currency_pair || '');
    const base = pair.indexOf('_') > 0 ? pair.slice(0, pair.indexOf('_')) : '';
    const quote = pair.indexOf('_') > 0 ? pair.slice(pair.indexOf('_') + 1) : '';
    const fc = String(f.fee_currency || '');
    const feeRaw = Number(f.fee) || 0;
    let fee = 0;
    if (fc && fc === base) fee = feeRaw * Number(px);
    else if (fc && fc === quote) fee = feeRaw;
    row = {
      venue: 'gate', market: 'spot', symbol: pair,
      side: String(f.side || '').toLowerCase() === 'buy' ? 'buy' : 'sell', posSide: '',
      order_px: '', exec_px: px, qty: qty,
      value: lbFmt(Number(px) * Number(qty)),
      fee: lbFmt(fee), closed_pnl: '0',
      kind: 'trade', funding: '0', ts: ts, exec_id: eid,
    };
  }
  if (!row.symbol || !(row.ts > 0)) return null;
  return row;
}
// ── Bitget (#2246) ─────────────────────────────────────────────────────────
// _bitget_fill_fee twin. (fee_raw, ccy) from any Bitget fill shape; fees
// arrive NEGATIVE when charged (the caller flips to cost-positive).
//  - WS orders-channel deltas (spot): flat `fillFee`/`fillFeeCoin` is the
//    PER-FILL fee and MUST win — the same delta also carries `feeDetail`,
//    but as the ORDER-CUMULATIVE list keyed `fee` (NOT `totalFee`), so a
//    partial fill would otherwise record the whole order's fee.
//  - WS orders-channel deltas (futures): NO flat fillFee, only the
//    cumulative list — trusted only when this fill IS the whole order so
//    far (baseVolume == accBaseVolume); else 0 and the delayed reconcile
//    corrects it. A parser reading only `totalFee` records every live fill
//    at ZERO fee.
//  - REST mix fills: feeDetail LIST of {totalFee, feeCoin}.
//  - REST spot fills: feeDetail DICT of {totalFee, feeCoin}.
//  - feeDetail may arrive as a JSON STRING on some feeds — parsed.
function lbBgFillFee(f) {
  const o = f || {};
  const v0 = lbNum(o.fillFee);
  if (v0 !== null) return { fee: v0, ccy: String(o.fillFeeCoin || '') };
  let fd = o.feeDetail;
  if (typeof fd === 'string') { try { fd = JSON.parse(fd); } catch (e) { fd = null; } }
  if (Array.isArray(fd)) {
    let tot = 0, ccy = '';
    for (const d0 of fd) {
      const d = d0 || {};
      let v = lbNum(d.totalFee);
      if (v === null) v = lbNum(d.fee);
      if (v !== null) { tot += Number(v); ccy = String(d.feeCoin || ccy); }
    }
    // #2251 the cumulative-trust rule keys on `accBaseVolume` PRESENCE, not
    // on baseVolume: ONLY an orders-channel delta carries a running order
    // total, and only there is the list order-cumulative. The REST mix fills
    // endpoint (/api/v2/mix/order/fills → baseVolume + PER-FILL
    // feeDetail[].totalFee, no accBaseVolume) and the private `fill` channel
    // have the same shape, so a baseVolume-keyed guard read both as
    // cumulative-and-unverifiable and recorded EVERY backfilled Bitget
    // futures fill at ZERO fee.
    if (o.accBaseVolume !== undefined && o.accBaseVolume !== null) {
      const bv = lbNum(o.baseVolume), acc = lbNum(o.accBaseVolume);
      // lbNum-trimmed strings compare exactly like the engine's Decimal ==.
      if (bv === null || acc === null || bv !== acc) return { fee: '0', ccy: '' };
    }
    return { fee: lbFmt(tot), ccy: ccy };
  }
  if (fd && typeof fd === 'object') {
    return { fee: lbNum(fd.totalFee) || '0', ccy: String(fd.feeCoin || '') };
  }
  return { fee: '0', ccy: '' };
}
// norm_bitget_fill twin. Accepts BOTH a REST fills row (mix
// /mix/order/fills and spot /spot/trade/fills) and a WS orders-channel fill
// delta, so the follow-on push lane reuses this untouched. exec_id =
// tradeId — the ONE id present on both paths, and the SAME id space the
// engine's normalizer uses, so "Save to server" dedupes against engine rows.
// Qty prefers `baseVolume`: a WS delta carries the ORDER's `size` alongside
// it and on spot that `size` is the QUOTE amount for buys, so size-first
// records quote qty (a $20 order rendered as 1.3M) and corrupts the
// average-entry replay. baseVolume is always the fill's BASE qty; REST rows
// don't carry it and keep using `size` (base there).
// #2251 Bitget futures position side. HEDGE mode runs a long AND a short
// stream on ONE symbol; with posSide blank both fill streams net against
// each other in the replay, the group never reaches a flat boundary and
// every fill folds into ONE permanently open trade. One-way rows
// ('*_single', posSide 'net', or no tradeSide at all) stay '' — the replay
// is then byte-identical to the pre-#2251 output for a one-way account.
function lbBgPosSide(f, market) {
  if (market === 'spot' || !f) return '';
  if (String(f.posMode || '').toLowerCase() === 'one_way_mode') return '';
  const ps = String(f.posSide || '').toLowerCase();
  if (ps === 'long' || ps === 'short') return ps;
  const tsd = String(f.tradeSide || '').toLowerCase();
  if (!tsd || tsd.indexOf('single') >= 0) return '';
  if (tsd.indexOf('long') >= 0) return 'long';
  if (tsd.indexOf('short') >= 0) return 'short';
  // bare 'open'/'close' (hedge mode): the POSITION side is the opening
  // direction — closing a long is a sell, closing a short is a buy.
  const buy = String(f.side || '').toLowerCase() === 'buy';
  if (tsd === 'open') return buy ? 'long' : 'short';
  if (tsd === 'close') return buy ? 'short' : 'long';
  return '';
}
// #2251 Bitget stamps SECONDS on some fill shapes (its own spot fills docs
// call cTime a "Unix second timestamp" while the example shows ms). A
// seconds value read as ms lands the fill in 1970: the poll cursor then
// asks for a 56-year window the venue rejects (zero rows forever) and the
// store's high-water mark never advances. Anything below the year-5138 ms
// boundary that is plausibly a seconds stamp is scaled up.
function lbBgTsMs(v) {
  let t = Math.floor(Number(v));
  if (!Number.isFinite(t) || t <= 0) return 0;
  if (t < 1e11) t = t * 1000;   // 1973-03 in ms — below this it is seconds
  return t;
}
// THIS fill's quantity in BASE units. `baseVolume` is always the fill's base
// qty and wins where present — a WS orders-channel delta carries the ORDER's
// `size` alongside it, and on a spot buy that size is the QUOTE amount
// (docs), so a size-first read logs a $20 order as 1.3M coins.
// #2251 `size` is still the only field the dedicated fill channel gives a
// spot row. Bitget is the venue that ships quote units where its siblings
// ship base, so when the row ALSO carries the filled quote total (`amount`)
// the reading that actually reproduces it wins — evidence from the venue's
// own numbers instead of an assumption about which unit this feed uses.
function lbBgQty(f, px) {
  const bv = lbNum(f.baseVolume);
  if (bv !== null && Number(bv) > 0) return bv;
  const sz = lbNum(f.size);
  if (sz === null || !(Number(sz) > 0)) return sz;
  const p = Number(px), amt = Number(lbNum(f.amount));
  if (p > 0 && amt > 0 && Math.abs(Number(sz) - amt) < Math.abs(Number(sz) * p - amt))
    return lbFmt(Number(sz) / p);
  return sz;
}
function lbNormBitgetFill(f, market) {
  if (!f || typeof f !== 'object') return null;
  // #2251 UPPERCASE: /api/v2/mix/order/fills returns the symbol lower-cased
  // ("ethusdt" in Bitget's own response example) while the WS instId, the
  // position rows, the board and the chart all use "ETHUSDT". Storing the
  // venue's casing verbatim split one instrument into two replay groups and
  // made the local rows invisible to every symbol-keyed consumer — chart
  // fill triangles and the break-even-from-local-replay lookup included.
  const sym = String(f.symbol || f.instId || '').toUpperCase();
  const mk = market === 'spot' ? 'spot' : 'futures';
  const px = lbNum(f.priceAvg) || lbNum(f.price) || lbNum(f.fillPrice) || '0';
  const sz = lbBgQty(f, px);
  if (!sym || sz === null || !(Number(sz) > 0)) return null;
  const side = String(f.side || '').toLowerCase() === 'buy' ? 'buy' : 'sell';
  const ff = lbBgFillFee(f);
  let feeD = -Number(ff.fee || 0);             // charged = negative → flip
  // Spot fees charged in the RECEIVED currency (base on buys) → ×price.
  if (mk === 'spot' && ff.ccy && sym.slice(-ff.ccy.length) !== ff.ccy) feeD = feeD * Number(px);
  // Python-`or` truthiness twin: '' / null / numeric 0 fall through, '0' does not.
  const tpick = (v) => (v === undefined || v === null || v === '' || v === 0) ? null : v;
  const traw = tpick(f.cTime) !== null ? f.cTime
             : (tpick(f.fillTime) !== null ? f.fillTime
             : (tpick(f.uTime) !== null ? f.uTime : 0));
  const ts = lbBgTsMs(traw);          // #2251 seconds-stamp guard
  return {
    venue: 'bitget', market: mk, symbol: sym,
    side: side, posSide: lbBgPosSide(f, mk),
    order_px: '', exec_px: px, qty: sz,
    value: lbFmt(Number(px) * Number(sz)),
    fee: lbFmt(feeD),
    closed_pnl: lbNum(f.profit) || '0',
    kind: 'trade', funding: '0',
    ts: ts,
    exec_id: String(f.tradeId || ''),
  };
}
// #2272 KuCoin fill timestamp → MILLISECONDS. norm_kucoin_fill's key order
// and nanosecond fold: futures `tradeTime` arrives in NANOSECONDS, spot
// `createdAt` in ms, and the private tradeOrders `match` delta stamps `ts` in
// ns on BOTH hosts. Spot and futures are two hosts with two clocks, so the
// fold is per-VALUE (>1e15 = ns), never per-market. The first POSITIVE key
// wins — a present-but-zero field falls through, the Python `or 0` chain.
function lbKcTsMs(f) {
  for (const k of ['tradeTime', 'createdAt', 'ts', 'orderTime']) {
    const v = Math.floor(Number((f || {})[k] || 0));
    if (!Number.isFinite(v) || v <= 0) continue;
    return v > 1e15 ? Math.floor(v / 1e6) : v;
  }
  return 0;
}
// #2272 is THIS row's fee readable as THIS fill's fee? A `match` delta off
// the private tradeOrders channel carries no fee field at all, and a fill
// recorded with a size but a zeroed fee is worse than no row: the replay
// carries the quantity while break-even divides real fees by an inflated net
// (bgFeeTrusted rule, KuCoin shape). Numeric = the venue's own value (an
// explicit 0, or a rebate, is a real value and stays admissible); missing or
// unparseable = fee UNKNOWN, and the REST fills poll owns the enrichment.
function lbKcFeeKnown(f) {
  return Number.isFinite(parseFloat((f || {}).fee));
}
// norm_kucoin_fill twin. Accepts a REST fills row (spot /api/v1/fills:
// size/price/fee/feeCurrency/tradeId/createdAt; futures /api/v1/fills:
// size in CONTRACTS/price/fee/tradeId/tradeTime ns) AND the private
// tradeOrders `match` delta (matchSize/matchPrice/tradeId/ts ns), so the
// push lane and the poll share one parser and one id space.
function lbNormKucoinFill(f, market, multiplier) {
  if (!f || typeof f !== 'object') return null;
  const sym = String(f.symbol || '');
  const mk = market === 'spot' ? 'spot' : 'futures';
  let sz = lbNum(f.matchSize);
  if (sz === null) sz = lbNum(f.size);
  if (!sym || sz === null || !(Number(sz) > 0)) return null;
  // Futures sizes are INTEGER CONTRACTS × the contract multiplier. A row
  // stored in contracts replays a 100× position on a 0.01-multiplier symbol,
  // so a missing multiplier must leave the raw value rather than guess 1.
  if (mk === 'futures') sz = kcBaseQty(sz, multiplier) || sz;
  const px = lbNum(f.matchPrice) || lbNum(f.price) || '0';
  const side = String(f.side || '').toLowerCase() === 'buy' ? 'buy' : 'sell';
  // KuCoin reports fees POSITIVE (a charge) and reconstruct SUBTRACTS
  // commission, so the value is kept as-is — no sign flip (Bitget's venue
  // reports charges negative and needs one; KuCoin does not).
  let fee = Number(lbNum(f.fee) || 0);
  const ccy = String(f.feeCurrency || '');
  if (mk === 'spot' && ccy && sym.slice(-ccy.length) !== ccy) fee = fee * Number(px);
  return {
    venue: 'kucoin', market: mk, symbol: sym,
    side: side, posSide: '',
    order_px: '', exec_px: px, qty: sz,
    value: lbFmt(Number(px) * Number(sz)),
    fee: lbFmt(fee),
    closed_pnl: '0',
    kind: 'trade', funding: '0',
    ts: lbKcTsMs(f),
    exec_id: String(f.tradeId || ''),
  };
}
// Exactly-once merge key: the fill's market + venue exec id (funding rows
// have no exec id → ts-keyed like the engine's funding handling).
function lbFillKey(f) {
  if (!f) return '';
  const eid = String(f.exec_id || '');
  // Side-INCLUSIVE (engine _fill_dedup_key parity): a self-match returns TWO
  // rows sharing ONE execID (opposite sides) — a side-less key silently
  // dropped the second leg and the trade stuck OPEN forever.
  if (eid) return String(f.market || '') + ':' + eid + ':'
    + String(f.side || '').toLowerCase();
  return String(f.market || '') + ':t' + String(f.ts || 0) + ':'
    + String(f.side || '') + ':' + String(f.qty || '');
}
// PRE-side-inclusive key ("market:eid") — used ONLY to honor tombstones
// written by older stores (never for new writes: a legacy key would
// cross-suppress the sibling leg of a self-match).
function lbFillKeyLegacy(f) {
  if (!f) return '';
  const eid = String(f.exec_id || '');
  if (eid) return String(f.market || '') + ':' + eid;
  return lbFillKey(f);
}
// Replay GROUP key — one position stream: venue|market|symbol|account. The
// ONE definition, shared by lbReconstruct's grouping and the per-group replay
// cache (#2234): if the two ever disagreed the cache would key groups the
// replay does not actually produce.
function lbGroupKey(f) {
  let aid = 0;
  try { aid = parseInt(f.aid, 10) || 0; } catch (e) { aid = 0; }
  return (f.venue || 'phemex') + '\u0000' + (f.market || '') + '\u0000'
    + (f.symbol || '') + '\u0000' + aid;
}
// Merge normalized fills into a scope store EXACTLY-ONCE: seen-key dedupe,
// tombstone respect (locally deleted fills stay deleted). Returns added n.
//
// #2234 ORDERED INSERTION: the store is kept ts-ordered, and fills arrive in
// time order, so an append preserves that invariant by itself. The old code
// re-sorted the ENTIRE row array on every merge — per fill, on the Electron
// main loop, against a 14k-row store — for an array that was already sorted.
// The full sort now runs ONLY when a merged row really lands out of order
// (backfill / re-import / server import), which is exactly when it is needed;
// the resulting array is identical either way (V8's sort is stable, so
// equal-ts rows keep insertion order in both paths). `sc._srt` counts the
// whole-store sorts and `sc._ep` is the replay-cache epoch — a non-append
// mutation cannot be detected from a group signature alone.
// `addedOut` (optional) collects the rows actually merged, so the caller can
// journal exactly those instead of re-deriving them (#2234).
function lbScopeMerge(sc, fills, addedOut) {
  if (!sc || !Array.isArray(fills)) return 0;
  if (!sc.seen) {
    sc.seen = {};
    for (const r of sc.rows) sc.seen[lbFillKey(r)] = 1;
  }
  let added = 0, unordered = false;
  let tail = sc.rows.length ? (Number(sc.rows[sc.rows.length - 1].ts) || 0) : -Infinity;
  for (const f of fills) {
    if (!f || !f.symbol || !(Number(f.qty) > 0) || !(Number(f.ts) > 0)) continue;
    const k = lbFillKey(f);
    // tombstones: honor BOTH the current side-inclusive key and the legacy
    // side-less key (older stores' deletes keep suppressing after upgrade)
    if (!k || sc.seen[k]
        || (sc.del && (sc.del[k] || sc.del[lbFillKeyLegacy(f)]))) continue;
    const ts = Number(f.ts) || 0;
    if (ts < tail) unordered = true; else tail = ts;
    sc.seen[k] = 1;
    sc.rows.push(f);
    if (addedOut) addedOut.push(f);
    added++;
  }
  if (added && unordered) {
    sc.rows.sort((a, b) => (a.ts || 0) - (b.ts || 0));
    sc._srt = (sc._srt | 0) + 1;
    sc._ep = (sc._ep | 0) + 1;
  }
  return added;
}
// #2268 PURE: correct ONE already-stored fill's fee in place. The merge above
// is exactly-once by fill key, so once a row is in the store NO later drain
// can ever replace it — a fee that only becomes readable after the row landed
// (Bitget spot: the fill channel records the execution, the suppressed orders
// twin carries the fee) has to be written to the STORED row itself, or the
// device blotter, its replay and every break-even derived from it keep the
// zero forever. Bounded backward scan: the twin rides the same burst as the
// fill it completes and rows are appended in ts order, so the target sits at
// the tail; a row further back than the window is reported as a MISS (0) for
// the caller to count, never silently left wrong.
// → 1 patched, -1 already carrying exactly that fee, 0 not found. `out`
// (optional) receives the STORED row: the caller's cache invalidation has to
// key on that row, not on the freshly normalized twin — a per-account slot
// stamps `aid` at drain time and the group key carries it, while the fill key
// does not.
const LB_FEEFIX_SCAN = 4000;
function lbFeeFixIn(sc, key, fee, out) {
  if (!sc || !Array.isArray(sc.rows) || !key || fee === undefined || fee === null) return 0;
  const rows = sc.rows;
  const stop = Math.max(0, rows.length - LB_FEEFIX_SCAN);
  for (let i = rows.length - 1; i >= stop; i--) {
    const r = rows[i];
    if (!r || lbFillKey(r) !== key) continue;
    if (out) out.row = r;
    if (String(r.fee) === String(fee)) return -1;
    r.fee = String(fee);
    return 1;
  }
  return 0;
}
// #2112 RE-IMPORT merge: rows fetched from the venue for an explicit
// [frm,to] window are VENUE TRUTH (blotter-reimport principle) — a local
// tombstone that would silently skip a re-asserted IN-WINDOW fill must
// YIELD (the sanctioned, window-scoped bypass), so previously pruned or
// deleted fills come back when the exchange re-asserts them. Out-of-window
// rows keep normal tombstone respect (an offline delete outside the window
// stays deleted). Dedup vs already-stored copies is unchanged (lbScopeMerge
// seen-key), so a second identical run adds 0. PURE (node-tested).
function lbReimportMerge(sc, fills, frm, to) {
  let tombCleared = 0;
  if (sc && sc.del && Array.isArray(fills)) {
    for (const f of fills) {
      if (!f) continue;
      const ts = Number(f.ts) || 0;
      if (!(ts >= frm && ts <= to)) continue;
      const k = lbFillKey(f);
      if (k && sc.del[k]) { delete sc.del[k]; tombCleared++; }
      const kl = lbFillKeyLegacy(f);
      if (kl && kl !== k && sc.del[kl]) { delete sc.del[kl]; tombCleared++; }
    }
  }
  const recv = Array.isArray(fills) ? fills.length : 0;
  const added = lbScopeMerge(sc, fills);
  return { added: added, skipped: recv - added, tombCleared: tombCleared };
}
// #2112 PURE binance window-pager step: decides the next startTime after a
// page of a myTrades/userTrades time-window walk. A FULL page must PROVE
// forward progress (lastTs > t0) — when every row of a full page shares the
// resume timestamp, time paging cannot advance without silently skipping
// the rest of that millisecond, so the step returns {stuck:true} and the
// caller must FAIL VISIBLY (venue-truth contract: a truncated fetch never
// masquerades as complete). Short page ⇒ window chunk covered ⇒ t1+1.
function lbBnWinStep(rowsLen, lastTs, t0, t1, limit) {
  if (rowsLen >= limit) {
    if (lastTs > t0) return { next: lastTs };   // resume AT boundary — dedupe absorbs overlap
    return { stuck: true };
  }
  return { next: t1 + 1 };
}
// #2038 SPOT truncated-history quarantine (local twin of the engine's #1849
// rule): cash spot can never be net short, so a spot scope whose fill replay
// goes NEGATIVE provably starts mid-position (the backfill window cut off
// earlier buys). Left as-is, the phantom offset swallows every later round
// trip into one stale OPEN group (open_ts weeks old → date filters hide it
// → "kraken spot never shows"). Fix: per spot scope, when the running signed
// sum dips below 0, quarantine the prefix up to the FIRST time the sum
// reaches its minimum — that is the first PROVABLE flat/floor point; the
// suffix replays from a true zero so round trips close honestly. Scopes that
// never go negative (no proof of truncation) are returned untouched, so
// normal long-only histories and deliberate sell-first stores replayed by
// lbReconstruct stay byte-identical. PURE (node-tested).
function lbSpotQuar(rows) {
  const out = { rows: [], quar: [] };
  if (!Array.isArray(rows) || !rows.length) { out.rows = rows || []; return out; }
  const EPS = 1e-12;
  const groups = {};   // spot trade scopes only
  let anySpot = false;
  for (const f of rows) {
    if (String(f && f.market || '') !== 'spot' || (f && f.kind === 'funding')) continue;
    anySpot = true;
    let aid = 0;
    try { aid = parseInt(f.aid, 10) || 0; } catch (e) { aid = 0; }
    const k = (f.venue || 'phemex') + '\u0000' + (f.symbol || '') + '\u0000' + aid;
    (groups[k] = groups[k] || []).push(f);
  }
  if (!anySpot) { out.rows = rows; return out; }
  const drop = new Set();   // fill object identity of quarantined rows
  for (const k of Object.keys(groups)) {
    const g = groups[k].slice().sort((a, b) => (a.ts || 0) - (b.ts || 0));
    let run = 0, min = 0, minI = -1;
    for (let i = 0; i < g.length; i++) {
      const q = Number(g[i].qty) || 0;
      run += (String(g[i].side || '').toLowerCase() === 'buy') ? q : -q;
      if (run < min - EPS) { min = run; minI = i; }
    }
    if (!(min < -EPS) || minI < 0) continue;   // never negative → no proof
    // #2098 dust-flat guard: kraken deducts spot fees (and sells sized off
    // the held balance round against the buys), so a flat-closing scalp
    // session can replay a hair NEGATIVE at its LAST fill — the "minimum"
    // then lands at/after the final sell and the old rule quarantined the
    // ENTIRE day's group (WINGS field log). A dip whose worth at the local
    // exec price is below the spot dust threshold is a CLOSED lot (same
    // LB_SPOT_DUST_USD rule lbReconstruct applies to remainders), NOT proof
    // of truncation — return the scope untouched; lbReconstruct's own dust
    // handling absorbs the oversell.
    const dipPx = Number(g[minI].exec_px) || 0;
    if (dipPx > 0 && (-min) * dipPx < LB_SPOT_DUST_USD) continue;
    if (!(dipPx > 0) && (-min) <= LB_EPS) continue; // no px: EPS-scale noise only
    for (let i = 0; i <= minI; i++) drop.add(g[i]);
    const parts = k.split('\u0000');
    out.quar.push({ venue: parts[0], market: 'spot', symbol: parts[1],
                    aid: parseInt(parts[2], 10) || 0,
                    before: Number(g[minI].ts) || 0, hidden: minI + 1 });
  }
  if (!drop.size) { out.rows = rows; return out; }
  out.rows = rows.filter((f) => !drop.has(f));
  return out;
}
// Per-market high-water mark (newest locally recorded fill ts) — the
// startup backfill fetches "everything since here".
function lbHwm(rows, market) {
  let hi = 0;
  for (const r of (rows || [])) {
    if (market && String(r.market || '') !== market) continue;
    if (Number(r.ts) > hi) hi = Number(r.ts);
  }
  return hi;
}
// #2230 no-news drain gate — pure, node-tested. lbDrain re-normalizes the live
// WS/UDS fill caches and merges them into the persisted scope on EVERY read,
// and every open window polls its own read: with a 14k-row store that is a
// full seen-index rebuild per window per beat on the main-process loop. When
// neither the source caches NOR the store have changed since the last drain,
// the drain provably cannot merge anything, so it is skipped — but only for
// `idleMs`, because a drain also self-heals rows the last pass could not
// normalize yet (HL '@N' spot wire coins, Gate contracts awaiting a
// multiplier), and that retry must keep happening.
const LB_DRAIN_IDLE_MS = 2000;
function lbDrainSkip(prev, sig, now, idleMs) {
  if (!prev || prev.sig !== sig) return false;
  const cap = (Number.isFinite(idleMs) && idleMs > 0) ? idleMs : LB_DRAIN_IDLE_MS;
  return (now - prev.t) < cap;
}
// Ring VERSION for that gate. Every live fill cache is a bounded ring, so row
// COUNT is not a change detector: at cap a push evicts the oldest row and
// appends a new one, leaving the length identical while the contents moved on
// (and, worse, while rows the gate skipped could roll off unseen). Every
// mutation therefore bumps a monotonic counter instead — O(1), no row touched.
// Length rides along only as a backstop for a mutation that forgets to touch.
function lbSrcTouch(F) {
  if (F) F.rev = (F.rev | 0) + 1;
  return F;
}
function lbSrcVer(F) {
  if (!F) return '-';
  return (F.rev | 0) + '.' + (Array.isArray(F.rows) ? F.rows.length : 0);
}
// INCREMENTAL DRAIN cursor (#2234). lbSrcTouch bumps `rev` exactly once per
// pushed row at every venue, so `rev` doubles as a total-pushed counter and
// (rev - prevRev) is how many rows arrived since the last drain. The drain
// re-normalizes only those, instead of re-walking all 400-600 cached rows of
// every ring on every poll — and it used to do that TWICE per merge, because
// the old gate signature carried the store length, so a successful merge
// invalidated the gate and forced another full pass on the very next poll.
// Falls back to the whole ring whenever the cursor cannot be trusted: first
// drain, a ring that reset or reconnected (rev went backwards), more rows
// pushed than the ring can hold (cap eviction dropped some unseen), or a
// caller-forced retry sweep for rows a previous pass could not normalize yet.
function lbRingFrom(prevRev, rev, len, full) {
  len = len | 0;
  if (len <= 0) return 0;
  if (full || prevRev == null || !Number.isFinite(Number(prevRev))) return 0;
  const pushed = (rev | 0) - (Number(prevRev) | 0);
  if (!(pushed >= 0) || pushed >= len) return 0;
  return len - pushed;
}
// --- Local-blotter persistence journal (#2234) -------------------------------
// The store used to be persisted by stringifying the WHOLE thing (3.4 MB) and
// writing it with a synchronous writeFileSync on the Electron main thread,
// debounced 1.5 s — i.e. landing right inside an order burst, repeatedly. The
// hot path now appends only the newly merged rows to a journal, and the full
// snapshot is written rarely, atomically, and out of the burst.
// PURE: one journal line (newline-delimited JSON, one batch per line).
function lbJrnLine(slot, rows) {
  return JSON.stringify({ s: String(slot), r: rows || [] }) + '\n';
}
// PURE: parse an append-only journal. A crash or force-quit mid-append leaves
// a TRUNCATED final line — it is counted and dropped, never guessed at; the
// fills it carried come back from the exchange through the startup gap
// backfill. Every surviving batch is replayed through lbScopeMerge on load,
// so duplicates and tombstoned rows are absorbed by the normal dedupe.
function lbJrnParse(text) {
  const out = [];
  let bad = 0;
  for (const ln of String(text || '').split('\n')) {
    if (!ln) continue;
    let v = null;
    try { v = JSON.parse(ln); } catch (e) { bad++; continue; }
    if (!v || typeof v !== 'object' || !v.s || !Array.isArray(v.r)) { bad++; continue; }
    out.push({ slot: String(v.s), rows: v.r });
  }
  return { batches: out, bad: bad };
}
// --- Main-loop phase timers (#2234, admin diag gate) -------------------------
// Freeze round 6 could only say a stall began 30-100 ms after "a push flush, a
// memo bust and a blotter ingest" — a neighbourhood, not a phase. These name
// each phase of the fill path separately so the next field log attributes a
// stall to one of them. PURE accumulators; the runtime only feeds them when
// the admin diag gate is live.
function lbPerfNew() { return { n: 0, ms: {}, mx: {}, t: 0 }; }
function lbPerfAdd(P, phase, ms) {
  if (!P || !phase || !(ms >= 0)) return P;
  P.ms[phase] = Math.round(((P.ms[phase] || 0) + ms) * 1000) / 1000;
  if (!(P.mx[phase] >= ms)) P.mx[phase] = Math.round(ms * 1000) / 1000;
  P.n++;
  return P;
}
// POSITION-AWARE size prune (the blotter-prune rule: NEVER a bare ts
// cutoff). When the scope exceeds `cap` rows, compute the cutoff ts that
// keeps ~cap newest rows, then per (venue|market|symbol|aid) group prune
// only the longest ts-ordered PREFIX that is entirely older than the
// cutoff AND ends with the running signed position flat. Funding rows
// (qty 0 semantics) prune by raw ts. Whole-group-stale groups drop
// wholesale. Returns the pruned rows array (input order preserved by ts).
function lbPruneRows(rows, cap) {
  cap = cap || 20000;
  if (!Array.isArray(rows) || rows.length <= cap) return rows || [];
  const sorted = rows.slice().sort((a, b) => (a.ts || 0) - (b.ts || 0));
  const cutoff = Number(sorted[sorted.length - cap].ts || 0);
  const groups = {};
  for (const r of sorted) {
    const gk = (r.venue || 'phemex') + '|' + (r.market || '') + '|'
      + (r.symbol || '') + '|' + String(r.aid || 0);
    (groups[gk] = groups[gk] || []).push(r);
  }
  const keep = [];
  for (const gk of Object.keys(groups)) {
    const g = groups[gk];
    const funding = g.filter((r) => r.kind === 'funding');
    const trade = g.filter((r) => r.kind !== 'funding');
    for (const fr of funding) if (Number(fr.ts) >= cutoff) keep.push(fr);
    if (!trade.length) continue;
    // NOTE: no whole-group ts shortcut here — a stale group that never
    // returned to flat is an OPEN position and must survive in full; the
    // flat-boundary walk below drops fully-flat stale groups by itself.
    // #2177 gate hedge-mode: a provably dual group tracks the two position
    // sides SEPARATELY — a flat boundary requires BOTH sides flat (net-zero
    // while long+short are concurrently open is NOT flat; two concurrent
    // open groups on one symbol must survive pruning).
    const dual = lbDualVenue(trade[0]) ? lbGateDualSplit(trade) : null;
    let pos = 0, posL = 0, posS = 0, cut = -1;
    for (let i = 0; i < trade.length; i++) {
      const r = trade[i];
      if (Number(r.ts) >= cutoff) break;
      const q = Number(r.qty) || 0;
      const signed = (String(r.side) === 'buy') ? q : -q;
      if (dual) {
        if (r.posSide === 'long') posL += signed; else posS += signed;
        if (Math.abs(posL) <= 1e-9 && Math.abs(posS) <= 1e-9) cut = i;
      } else {
        pos += signed;
        if (Math.abs(pos) <= 1e-9) cut = i;  // flat boundary inside the stale prefix
      }
    }
    for (let i = cut + 1; i < trade.length; i++) keep.push(trade[i]);
  }
  keep.sort((a, b) => (a.ts || 0) - (b.ts || 0));
  return keep;
}
// #1969 Binance startup-backfill pagers — I/O injected via `bnReq(market,
// path, params)` (markets: 'spot'/'futures' signed, 'spotPub' unsigned big-
// cap GET) so node tests drive them with a fake requester. Futures:
// symbol-less GET /fapi/v1/userTrades over ≤7d windows (limit 1000; a full
// page continues the SAME window from lastRow.time+1). Spot: /api/v3/myTrades
// REQUIRES a symbol — page per symbol with fromId (>= the local high-water
// trade id) when known, else one most-recent page. `covOk:false` whenever
// coverage is knowably incomplete (call-cap hit, overflowing first page,
// too many symbols) — the panel must NOT suppress server legs on it.
// #1979: 25/60 was too tight — a real 30-pair spot universe tripped the cap
// and kept Binance in ramp mode. 50 pairs comfortably covers realistic
// holdings; the call budget is raised in proportion (50 spot pages + futures
// windows) so the cap-hit path still fires honestly on truly huge universes.
const LB_BN_MAX_CALLS = 90;
const LB_BN_FUT_WIN_MS = 7 * 86400 * 1000;
const LB_BN_SPOT_SYM_CAP = 50;
// #2160 re-import window precheck: the walk needs at least one signed call
// per futures 7d-chunk plus one per pair × spot day-chunk — a LOWER BOUND
// of the real call count (full pages re-page inside a chunk). If even the
// minimum exceeds LB_BN_MAX_CALLS the walk is GUARANTEED to fail, so
// reject before any trade fetch starts (field case: ~26d × 12 pairs burned
// 65s / ~580 requests before the mid-fetch cap fired). Returns null when
// the window may fit; the in-loop cap stays as the honest backstop.
const LB_RI_BN_SPOT_WIN_MS = 24 * 3600 * 1000 - 60000;   // myTrades span cap
function lbBnRiEstimate(market, spanMs, pairs) {
  const fut = market !== 'spot' ? Math.ceil(spanMs / LB_BN_FUT_WIN_MS) : 0;
  const spotChunks = market !== 'futures' ? Math.ceil(spanMs / LB_RI_BN_SPOT_WIN_MS) : 0;
  return { fut: fut, spotChunks: spotChunks,
           total: fut + (pairs | 0) * spotChunks };
}
function lbBnRiPrecheck(market, frm, to, pairs) {
  const est = lbBnRiEstimate(market, Math.max(1, to - frm), pairs);
  if (est.total <= LB_BN_MAX_CALLS) return null;
  // largest whole-day window that fits the budget for THIS pair count —
  // an actionable retry hint (0 = even one day is over).
  let maxDays = 0;
  for (let d = 1; d <= 92; d++) {
    if (lbBnRiEstimate(market, d * 86400 * 1000, pairs).total
        > LB_BN_MAX_CALLS) break;
    maxDays = d;
  }
  return { pairs: pairs | 0, chunks: est.spotChunks, futChunks: est.fut,
    reqs: est.total, maxDays: maxDays,
    msg: 'Window too large: ' + (pairs | 0) + ' pairs × ' + est.spotChunks
      + ' day-chunks' + (est.fut ? ' + ' + est.fut + ' futures chunks' : '')
      + ' = ' + est.total + ' requests (budget ' + LB_BN_MAX_CALLS + ').'
      + (maxDays > 0
         ? ' Max ~' + maxDays + ' days for your pair count.'
         : ' Re-import futures and spot separately or reduce the pair count.') };
}
const LB_BN_QUOTES = ['USDT', 'USDC', 'FDUSD', 'TUSD', 'BUSD', 'BTC', 'ETH', 'BNB', 'EUR', 'TRY'];
// Spot symbol UNIVERSE for backfill: local rows alone miss never-recorded
// pairs, so derive from the account itself — held assets (spot balances) ×
// common quotes via exchangeInfo, plus open-order symbols. A failed read
// returns ok:false — coverage UNKNOWN, caller keeps the server blotter.
async function lbBnSpotUniverse(bnReq, localSyms) {
  const syms = {};
  for (const s of (localSyms || [])) if (s) syms[String(s).toUpperCase()] = 1;
  const acct = await bnReq('spot', '/api/v3/account', []);
  if (!acct || !acct.ok) return { ok: false, message: 'Binance spot account read: ' + ((acct && acct.message) || 'failed') };
  const held = {};
  for (const b of ((acct.data && acct.data.balances) || [])) {
    if ((Number(b.free) || 0) + (Number(b.locked) || 0) > 0) held[String(b.asset || '').toUpperCase()] = 1;
  }
  const oo = await bnReq('spot', '/api/v3/openOrders', []);
  if (!oo || !oo.ok) return { ok: false, message: 'Binance spot open-orders read: ' + ((oo && oo.message) || 'failed') };
  for (const o of (Array.isArray(oo.data) ? oo.data : [])) {
    if (o && o.symbol) syms[String(o.symbol).toUpperCase()] = 1;
  }
  // stables/fiat are never a traded BASE worth enumerating; BTC/ETH/BNB are
  // quotes too but commonly held as bases — keep them.
  const LB_BN_STABLES = ['USDT', 'USDC', 'FDUSD', 'TUSD', 'BUSD', 'EUR', 'TRY'];
  const bases = Object.keys(held).filter((a) => LB_BN_STABLES.indexOf(a) < 0);
  if (bases.length) {
    // #1977: unfiltered exchangeInfo grew past 16MB (permission sets are
    // ~90% of the body) — showPermissionSets=false shrinks it ~10×.
    const xi = await bnReq('spotPub', '/api/v3/exchangeInfo',
                           [['showPermissionSets', 'false']]);
    if (!xi || !xi.ok) return { ok: false, message: 'Binance exchangeInfo: ' + ((xi && xi.message) || 'failed') };
    for (const s of ((xi.data && xi.data.symbols) || [])) {
      if (!s || s.status !== 'TRADING') continue;
      if (held[String(s.baseAsset || '').toUpperCase()]
          && LB_BN_QUOTES.indexOf(String(s.quoteAsset || '').toUpperCase()) >= 0)
        syms[String(s.symbol).toUpperCase()] = 1;
    }
  }
  return { ok: true, syms: Object.keys(syms).sort() };
}
// #1975 Kraken budget-aware backfill retry — a `kr_budget` deferral
// (skipped:true) at app start just means the startup account-read burst
// drained the rate-points ledger; wait for it to refill and retry (bounded,
// exponential backoff). Any OTHER failure — and budget still exhausted past
// the retry bound — surfaces honestly. I/O injected (hbFn/sleepFn/diagFn)
// so node tests drive it with fakes.
const LB_KR_BF_TRIES = 6;
const LB_KR_BF_WAIT0_MS = 15000;
const LB_KR_BF_WAIT_MAX_MS = 120000;
// #2168: optional `resv` ({ acquire, release }) — a rate-points ledger
// reservation held across the WHOLE ladder (attempts AND the refill sleeps
// between them — releasing during a sleep would let polling eat the refill
// again). Always released (finally) — success, honest fail, or throw.
async function lbKrBackfillRetry(hbFn, intent, sleepFn, diagFn, resv) {
  if (resv && typeof resv.acquire === 'function') resv.acquire();
  try {
    let waitMs = LB_KR_BF_WAIT0_MS;
    for (let attempt = 1; ; attempt++) {
      const r = await hbFn(intent);
      if (!r) return { ok: false, message: 'backfill failed', bfTries: attempt };
      if (r.ok || !r.skipped || attempt >= LB_KR_BF_TRIES)
        return Object.assign({}, r, { bfTries: attempt });
      if (diagFn) diagFn(attempt, waitMs);
      await sleepFn(waitMs);
      waitMs = Math.min(waitMs * 2, LB_KR_BF_WAIT_MAX_MS);
    }
  } finally {
    if (resv && typeof resv.release === 'function') resv.release();
  }
}
async function lbBnBackfill(bnReq, futFrm, to, spotSyms, spotFrom, pageGapMs) {
  const out = { ok: true, fills: [], gap: false, covOk: true, notes: [] };
  let calls = 0;
  let t0 = futFrm;
  while (t0 < to) {
    if (calls >= LB_BN_MAX_CALLS) { out.gap = true; out.covOk = false; out.notes.push('futures window cap hit'); break; }
    const t1 = Math.min(t0 + LB_BN_FUT_WIN_MS, to);
    calls++;
    const r = await bnReq('futures', '/fapi/v1/userTrades',
      [['startTime', String(t0)], ['endTime', String(t1)], ['limit', '1000']]);
    if (!r || !r.ok) return { ok: false, message: 'Binance futures backfill: ' + ((r && r.message) || 'request failed') };
    const rows = Array.isArray(r.data) ? r.data : [];
    let lastTs = 0;
    for (const raw of rows) {
      const f = lbNormBnFutRest(raw);
      if (f) { out.fills.push(f); if (f.ts > lastTs) lastTs = f.ts; }
    }
    if (rows.length >= 1000 && lastTs > t0) t0 = lastTs + 1;   // full page → continue same window
    else t0 = t1 + 1;
    if (t0 < to && pageGapMs) await new Promise((rs) => setTimeout(rs, pageGapMs));
  }
  const symList = (spotSyms || []).filter((s) => /^[A-Za-z0-9]{1,32}$/.test(String(s)));
  // #1979: when trimming to the cap, page watermarked (locally-known) pairs
  // FIRST — the overflow note then names only never-traded pairs.
  const hasWm = (s) => spotFrom && Number(spotFrom[s]) > 0;
  symList.sort((a, b) => (hasWm(b) - hasWm(a)) || (a < b ? -1 : a > b ? 1 : 0));
  if (symList.length > LB_BN_SPOT_SYM_CAP) {
    out.gap = true; out.covOk = false;
    out.notes.push('too many spot pairs (' + symList.length + ' > ' + LB_BN_SPOT_SYM_CAP + ')');
  }
  for (const sym of symList.slice(0, LB_BN_SPOT_SYM_CAP)) {
    let fromId = spotFrom && Number(spotFrom[sym]) > 0 ? Math.floor(Number(spotFrom[sym])) : null;
    for (;;) {
      if (calls >= LB_BN_MAX_CALLS) { out.gap = true; out.covOk = false; out.notes.push('spot call cap hit at ' + sym); break; }
      calls++;
      const params = [['symbol', String(sym).toUpperCase()], ['limit', '1000']];
      if (fromId != null) params.push(['fromId', String(fromId)]);
      const r = await bnReq('spot', '/api/v3/myTrades', params);
      if (!r || !r.ok) return { ok: false, message: 'Binance spot backfill (' + sym + '): ' + ((r && r.message) || 'request failed') };
      const rows = Array.isArray(r.data) ? r.data : [];
      let maxId = fromId != null ? fromId : 0;
      for (const raw of rows) {
        const f = lbNormBnSpotRest(raw);
        if (f) out.fills.push(f);   // keep the WHOLE page — dedupe absorbs overlap
        const rid = Math.floor(Number(raw && raw.id) || 0);
        if (rid > maxId) maxId = rid;
      }
      if (fromId == null) {
        // no local watermark for this symbol: one most-recent page only —
        // a FULL page means history extends past it (coverage incomplete).
        if (rows.length >= 1000) { out.gap = true; out.covOk = false; out.notes.push('spot ' + sym + ': >1000 trades — older history not fetched'); }
        break;
      }
      if (rows.length < 1000) break;
      fromId = maxId + 1;
      if (pageGapMs) await new Promise((rs) => setTimeout(rs, pageGapMs));
    }
  }
  return out;
}
// reconstruct_trades twin: normalized fills → OPEN + CLOSED round-trip
// trade rows in the engine's output schema (id/dir/vol/net/pct/fee/…),
// plus a local-only `keys` array (contributing fill keys — offline delete
// sweeps exactly these). Float arithmetic with lbFmt/lbMoney display
// rounding; golden-set parity vs the engine replay is test-guarded.
const LB_EPS = 1e-9;
const LB_SPOT_DUST_USD = 1;
function lbReconstruct(fills, displayMap) {
  const groups = {};
  for (const f of (fills || [])) {
    let aid = 0;
    try { aid = parseInt(f.aid, 10) || 0; } catch (e) { aid = 0; }
    const key = lbGroupKey(f);
    const g = groups[key] = groups[key]
      || { venue: f.venue || 'phemex', market: f.market || '', symbol: f.symbol || '', aid: aid, trade: [], funding: [] };
    (f.kind === 'funding' ? g.funding : g.trade).push(f);
  }
  // #2177 gate hedge-mode: when a gate futures group is provably dual-mode
  // (every row posSide-tagged, both sides present) split it into two
  // independent lot streams — long/short position fills must never net
  // against each other. Funding rows aren't side-attributable (gate hands
  // one aggregate row) → they ride the LONG stream only (no double count).
  for (const key of Object.keys(groups)) {
    const G = groups[key];
    if (!lbDualVenue(G)) continue;
    const sp = lbGateDualSplit(G.trade);
    if (!sp) continue;
    delete groups[key];
    groups[key + '\u0000l'] = { ...G, trade: sp.long };
    groups[key + '\u0000s'] = { ...G, trade: sp.short, funding: [] };
  }
  const out = [];
  for (const key of Object.keys(groups)) {
    const G = groups[key];
    const tradeRows = G.trade.slice().sort((a, b) => (a.ts || 0) - (b.ts || 0));
    const fundingRows = G.funding.slice().sort((a, b) => (a.ts || 0) - (b.ts || 0));
    let pos = 0, cur = null;
    const nnew = (dir, ts) => ({
      venue: G.venue, aid: G.aid, market: G.market, symbol: G.symbol,
      dir: dir, open_ts: ts, close_ts: ts,
      open_qty: 0, open_notional: 0, close_qty: 0, close_notional: 0,
      commission: 0, closed_pnl: 0, fee_alt: {}, fills: [], keys: [],
    });
    // #2234 contributing-key dedupe index. `tr.keys.indexOf(k)` is a LINEAR
    // scan per fill, so a long-lived position (thousands of fills in one
    // trade) made the whole replay quadratic — measured 130 ms for a 14.4k
    // store, 28 ms with this index, byte-identical output. Kept OUT of the
    // trade row (a Map keyed by the row object) so the emitted payload is
    // unchanged.
    const kseen = new Map();
    const add = (tr, row, portion, kind) => {
      const px = Number(row.exec_px) || 0;
      const val = px * portion;
      const rowq = Number(row.qty) || 0;
      const frac = rowq > 0 ? portion / rowq : 1;
      const fee = (Number(row.fee) || 0) * frac;
      tr.commission += fee;
      if (kind === 'open') { tr.open_qty += portion; tr.open_notional += val; }
      else {
        tr.close_qty += portion; tr.close_notional += val;
        tr.closed_pnl += (Number(row.closed_pnl) || 0) * frac;
      }
      tr.close_ts = row.ts != null ? row.ts : tr.close_ts;
      const entry = {
        type: kind, side: row.side,
        price: row.order_px || '', exec_price: row.exec_px || '',
        qty: lbFmt(portion), value: lbMoney(val), fee: lbMoney(fee),
        ts: row.ts || 0,
      };
      const fa = String(row.fee_alt || '');
      if (fa) {
        const parts = fa.split(' ');
        if (parts.length === 2 && Number.isFinite(Number(parts[0]))) {
          const amt = Number(parts[0]) * frac;
          tr.fee_alt[parts[1]] = (tr.fee_alt[parts[1]] || 0) + amt;
          entry.fee_alt = lbFmt(amt) + ' ' + parts[1];
        }
      }
      tr.fills.push(entry);
      const k = lbFillKey(row);
      if (k) {
        let ks = kseen.get(tr);
        if (!ks) { ks = new Set(); kseen.set(tr, ks); }
        if (!ks.has(k)) { ks.add(k); tr.keys.push(k); }
      }
    };
    const feeAltOut = (tr) => {
      const parts = [];
      for (const c of Object.keys(tr.fee_alt).sort()) {
        if (tr.fee_alt[c] !== 0) parts.push(lbFmt(tr.fee_alt[c]) + ' ' + c);
      }
      if (parts.length) tr.out.fee_alt = parts.join(' + ');
    };
    const finalize = (tr) => {
      let fund = 0;
      for (const fr of fundingRows) {
        if (tr.open_ts <= fr.ts && fr.ts <= tr.close_ts) fund += Number(fr.funding) || 0;
      }
      const openPx = tr.open_qty > 0 ? tr.open_notional / tr.open_qty : 0;
      const closePx = tr.close_qty > 0 ? tr.close_notional / tr.close_qty : 0;
      let net;
      if (tr.market === 'spot') net = tr.close_notional - tr.open_notional - tr.commission;
      else {
        net = tr.closed_pnl - tr.commission - fund;
        // #2177 gate: engine stamps per-fill closed PnL '0' by design (Gate
        // hands none) — NET must come from the matched-notional fallback or
        // every gate futures round-trip nets −fees.
        if ((tr.venue === 'bybit' || tr.venue === 'kucoin' || tr.venue === 'bitmex'
             || tr.venue === 'kraken' || tr.venue === 'gate')
            && tr.closed_pnl === 0 && tr.close_qty > 0) {
          const sign = tr.dir === 'long' ? 1 : -1;
          net = sign * (tr.close_notional - tr.open_notional) - tr.commission - fund;
        }
      }
      let pct = 0;
      if (openPx > 0 && closePx > 0) {
        const raw = (closePx - openPx) / openPx * 100;
        pct = tr.dir === 'long' ? raw : -raw;
      }
      let tid = tr.market + ':' + tr.symbol + ':' + tr.open_ts + ':' + tr.close_ts;
      if (tr.aid) tid = 'a' + tr.aid + ':' + tid;
      tr.out = {
        id: tr.venue === 'phemex' ? tid : tr.venue + ':' + tid,
        venue: tr.venue,
        ...(tr.aid ? { aid: tr.aid } : {}),
        market: tr.market, symbol: tr.symbol, display: tr.symbol,
        dir: tr.dir,
        vol_base: lbFmt(tr.open_qty), vol_usd: lbMoney(tr.open_notional),
        open_px: lbFmt(openPx), close_px: lbFmt(closePx),
        pct: lbMoney(pct), net: lbMoney(net),
        commission: lbMoney(tr.commission), funding: lbMoney(fund),
        open_ts: tr.open_ts, close_ts: tr.close_ts,
        fills: tr.fills, keys: tr.keys,
      };
      feeAltOut(tr);
    };
    const finalizeOpen = (tr) => {
      let fund = 0;
      for (const fr of fundingRows) if (fr.ts >= tr.open_ts) fund += Number(fr.funding) || 0;
      let remaining = tr.open_qty - tr.close_qty;
      if (remaining < 0) remaining = 0;
      const openPx = tr.open_qty > 0 ? tr.open_notional / tr.open_qty : 0;
      let oid = tr.market + ':' + tr.symbol + ':' + tr.open_ts + ':open';
      if (tr.aid) oid = 'a' + tr.aid + ':' + oid;
      tr.out = {
        id: tr.venue === 'phemex' ? oid : tr.venue + ':' + oid,
        venue: tr.venue,
        ...(tr.aid ? { aid: tr.aid } : {}),
        market: tr.market, symbol: tr.symbol, display: tr.symbol,
        dir: tr.dir, open: true,
        vol_base: lbFmt(remaining), vol_usd: lbMoney(openPx * remaining),
        open_px: lbFmt(openPx), close_px: '',
        pct: 0, net: 0,
        commission: lbMoney(tr.commission), funding: lbMoney(fund),
        open_ts: tr.open_ts, close_ts: null,
        fills: tr.fills, keys: tr.keys,
      };
      feeAltOut(tr);
    };
    const dustRemainder = (tr, posAbs) => {
      if (tr.market !== 'spot') return false;
      if (tr.close_qty <= 0 || tr.open_qty <= 0) return false;
      const openPx = tr.open_notional / tr.open_qty;
      if (openPx <= 0) return false;
      return posAbs * openPx < LB_SPOT_DUST_USD;
    };
    const finalizeDust = (tr) => {
      const matched = tr.close_qty;
      const openPx = tr.open_qty > 0 ? tr.open_notional / tr.open_qty : 0;
      tr.open_qty = matched;
      tr.open_notional = openPx * matched;
      finalize(tr);
    };
    for (const row of tradeRows) {
      const q = Number(row.qty) || 0;
      if (q <= 0) continue;
      const buy = row.side === 'buy';
      const signed = buy ? q : -q;
      if (cur === null) {
        cur = nnew(buy ? 'long' : 'short', row.ts || 0);
        add(cur, row, q, 'open');
        pos = signed;
        continue;
      }
      const reducing = (cur.dir === 'long' && !buy) || (cur.dir === 'short' && buy);
      if (!reducing) { add(cur, row, q, 'open'); pos += signed; }
      else {
        const closing = Math.min(q, Math.abs(pos));
        add(cur, row, closing, 'close');
        const remaining = q - closing;
        pos += buy ? closing : -closing;
        if (Math.abs(pos) <= LB_EPS) {
          finalize(cur); out.push(cur.out); cur = null; pos = 0;
          if (remaining > LB_EPS) {
            const px = Number(row.exec_px) || 0;
            if (G.market === 'spot' && px > 0 && remaining * px < LB_SPOT_DUST_USD) continue;
            cur = nnew(buy ? 'long' : 'short', row.ts || 0);
            add(cur, row, remaining, 'open');
            pos = buy ? remaining : -remaining;
          }
        } else if (dustRemainder(cur, Math.abs(pos))) {
          finalizeDust(cur); out.push(cur.out); cur = null; pos = 0;
        }
      }
    }
    if (cur !== null && Math.abs(pos) > LB_EPS) {
      if (dustRemainder(cur, Math.abs(pos))) finalizeDust(cur);
      else finalizeOpen(cur);
      out.push(cur.out);
    }
  }
  const dm = displayMap || {};
  for (const tr of out) {
    const d = dm[(tr.venue || 'phemex') + '|' + tr.market + '|' + tr.symbol]
      || dm[tr.market + '|' + tr.symbol];
    if (d) tr.display = d;
  }
  lbTradeOrder(out);
  const seen = {};
  for (const tr of out) {
    const base = tr.id;
    const n = seen[base] || 0;
    if (n) tr.id = base + '#' + n;
    seen[base] = n + 1;
  }
  return out;
}
// The ONE trade ordering: OPEN rows first, then newest ts. Sorts in place and
// is STABLE (V8), so equal-key rows keep their incoming order. Shared by
// lbReconstruct and the per-group replay cache (#2234) — a second copy of
// this comparator would let the cached and uncached paths order ties
// differently, which is exactly the kind of silent reordering the local
// blotter must never do.
function lbTradeOrder(out) {
  out.sort((a, b) => {
    const ka = a.open ? 0 : 1, kb = b.open ? 0 : 1;
    if (ka !== kb) return ka - kb;
    const ta = a.open ? (a.open_ts || 0) : (a.close_ts || 0);
    const tb = b.open ? (b.open_ts || 0) : (b.close_ts || 0);
    return tb - ta;
  });
  return out;
}
// PURE (#2234) PER-GROUP MEMOIZED REPLAY — the fix for the per-fill freeze.
//
// lbReconstruct is O(store): 130 ms measured over a 14.4k-row store, and
// `execLblotTrades` re-ran it on EVERY fill (a merge changes rows.length,
// which invalidates the whole-store cache), so one 14-order Binance burst
// cost thirteen full replays on the Electron main loop — the recurring
// 292-408 ms stalls of the 2026-08-15 field log. A fill only ever touches ONE
// (venue|market|symbol|aid) group, so the replay is split per group, memoized
// by a group signature, and only the groups that actually changed are
// recomputed. Unchanged groups reuse their trade rows AND their serialized
// JSON fragment verbatim, so the once-per-rev payload stringify stops being
// O(store) too.
//
// Output is IDENTICAL to lbReconstruct(fills, displayMap):
//   • every group is still replayed by lbReconstruct itself (same lot machine,
//     same gate hedge split, same within-group id dedupe),
//   • groups are concatenated in lbReconstruct's own group order — including
//     its re-keying of a dual-mode gate futures group to the END,
//   • the concatenation goes through the same stable lbTradeOrder, so ties
//     break the same way,
//   • cross-group id collisions cannot exist (the trade id carries
//     venue+market+symbol+aid), so the global dedupe pass has nothing left to
//     do and is not repeated (it would double-suffix cached rows).
// `cache` is caller-owned ({} to start) and is pruned of vanished groups.
function lbReplay(cache, fills, displayMap, dmSig, wantJson) {
  const order = [], map = Object.create(null);
  for (const f of (fills || [])) {
    if (!f) continue;
    const k = lbGroupKey(f);
    let g = map[k];
    if (!g) { g = map[k] = []; order.push(k); }
    g.push(f);
  }
  const g0 = cache.g || (cache.g = Object.create(null));
  const dsig = String(dmSig || '');
  const keep = Object.create(null);
  const front = [], back = [];
  let recomputed = 0, replayed = 0;
  for (const k of order) {
    const rows = map[k];
    const sig = rows.length + '|' + lbFillKey(rows[0]) + '|'
      + lbFillKey(rows[rows.length - 1]) + '|' + dsig;
    let e = g0[k];
    if (!e || e.sig !== sig) {
      const first = rows[0];
      // mirror lbReconstruct's gate hedge re-keying (a split group is deleted
      // and re-added, i.e. moved to the end of the group order)
      let dual = false;
      if (lbDualVenue(first)) {
        dual = !!lbGateDualSplit(rows.filter((r) => r.kind !== 'funding'));
      }
      e = g0[k] = { sig: sig, dual: dual, tj: null,
                    trades: lbReconstruct(rows, displayMap || null) };
      recomputed++; replayed += rows.length;
    }
    if (wantJson && !e.tjs) e.tjs = e.trades.map((t) => JSON.stringify(t));
    keep[k] = 1;
    (e.dual ? back : front).push(e);
  }
  for (const k of Object.keys(g0)) if (!keep[k]) delete g0[k];
  const all = front.concat(back);
  const trades = [];
  for (const e of all) for (const t of e.trades) trades.push(t);
  lbTradeOrder(trades);
  // The once-per-rev serialized payload is assembled from PER-TRADE fragments
  // cached with their group (the sorted array interleaves groups, so only a
  // per-trade fragment can be reused). A whole-payload JSON.stringify measured
  // 6.2 MB/6.2 ms per rev on the field store — now only the changed group's
  // rows are re-stringified. Any lookup miss falls back to the plain stringify,
  // which is the identical string by construction.
  let tj;
  if (wantJson) {
    const m = new Map();
    for (const e of all) {
      for (let i = 0; i < e.trades.length; i++) m.set(e.trades[i], e.tjs[i]);
    }
    let ok = true;
    const parts = new Array(trades.length);
    for (let i = 0; i < trades.length; i++) {
      const s = m.get(trades[i]);
      if (s == null) { ok = false; break; }
      parts[i] = s;
    }
    tj = ok ? '[' + parts.join(',') + ']' : JSON.stringify(trades);
  }
  return { trades: trades, tj: tj, groups: order.length,
           recomputed: recomputed, replayed: replayed };
}

// --- Bybit pure builders ----------------------------------------------------
function bybitSign(secret, tsMs, apiKey, recvWindow, payload) {
  const msg = String(tsMs) + String(apiKey) + String(recvWindow) + String(payload);
  return crypto.createHmac('sha256', String(secret)).update(msg, 'utf8').digest('hex');
}

// #2051 Bybit private-WS auth signature — HMAC-SHA256 hex over
// 'GET/realtime<expires>' (engine bybit_ws_auth_sig twin).
function bybWsAuthSig(secret, expiresMs) {
  return crypto.createHmac('sha256', String(secret))
    .update('GET/realtime' + String(expiresMs), 'utf8').digest('hex');
}

// #2051 Bybit V5 order-topic status → ledger effect (engine
// _OPEN_ORD_STATUSES twin): open-family statuses upsert the badge row,
// everything else removes it. Empty status = no effect (malformed row).
function bybOrdEffect(status) {
  const s = String(status || '');
  if (!s) return null;
  return (s === 'New' || s === 'PartiallyFilled' || s === 'Untriggered' ||
          s === 'Created') ? 'add' : 'gone';
}

const BYBIT_ERRORS = {
  10003: 'Invalid API key',
  10004: 'Invalid request signature — re-enter your API keys',
  10002: 'Request timestamp outside recvWindow — server clock skew',
  10005: 'API key lacks the required permissions',
  10006: 'Rate limited by Bybit — retry shortly',
  10018: 'Rate limited by Bybit — retry shortly',
  110004: 'Insufficient wallet balance',
  110007: 'Insufficient available balance',
  110017: 'Reduce-only order would increase the position',
  110043: 'Leverage not modified',
  170131: 'Insufficient balance',
  170213: 'Order does not exist or is already filled/cancelled',
  110001: 'Order does not exist',
};

function bybitErrorMessage(code, rawMsg) {
  const n = parseInt(code, 10);
  const msg = isNaN(n) ? undefined : BYBIT_ERRORS[n];
  if (msg) return msg;
  const tail = rawMsg ? ': ' + rawMsg : '';
  return 'Bybit error ' + code + tail;
}

function bybitOrderBody(market, symbol, side, ordType, qty, price, clOrdID, flags) {
  const f = flags || {};
  const cat = market === 'futures' ? 'linear' : 'spot';
  const sideU = String(side).toLowerCase() === 'buy' ? 'Buy' : 'Sell';
  const t = String(ordType).toLowerCase();
  const isStop = t === 'stop' || t === 'stop_limit' || t === 'tp_market';
  const body = {
    category: cat, symbol: String(symbol), side: sideU,
    orderType: (t === 'limit' || t === 'stop_limit') ? 'Limit' : 'Market',
    qty: String(qty),
  };
  if (t === 'limit' || t === 'stop_limit') {
    body.price = String(price);
    body.timeInForce = 'GTC';
  }
  if (cat === 'spot') {
    if (body.orderType === 'Market') {
      body.marketUnit = sideU === 'Buy' ? 'quoteCoin' : 'baseCoin';
    }
  } else {
    body.positionIdx = 0;
    if (f.reduceOnly) body.reduceOnly = true;
  }
  if (isStop) {
    body.triggerPrice = String(f.trigger);
    body.triggerBy = 'MarkPrice';
    if (f.triggerDirection === 1 || f.triggerDirection === 2) {
      body.triggerDirection = f.triggerDirection;
    }
  }
  body.orderLinkId = String(clOrdID);
  return body;
}

function bybPositionRows(data) {
  const rows = [];
  const lst = (((data || {}).result || {}).list) || [];
  for (const p of Array.isArray(lst) ? lst : []) {
    try {
      const size = bnNum(p.size) || '0';
      const side = String(p.side || '');
      if (Number(size) === 0 || (side !== 'Buy' && side !== 'Sell')) continue;
      rows.push({ symbol: p.symbol, side: side, size: size, mark: bnNum(p.markPrice) });
    } catch (e) { /* skip */ }
  }
  return rows;
}

// --- OKX pure builders --------------------------------------------------------
function okxSign(secret, ts, method, path, body) {
  const msg = String(ts) + String(method).toUpperCase() + String(path) + String(body || '');
  return crypto.createHmac('sha256', String(secret)).update(msg, 'utf8').digest('base64');
}

function okxTs(nowMs) {
  const d = new Date(nowMs != null ? nowMs : Date.now());
  return d.toISOString().slice(0, 23) + 'Z';
}

const OKX_ERRORS = {
  50111: 'Invalid API key',
  50113: 'Invalid request signature — re-enter your API keys',
  50105: 'Invalid passphrase — re-enter your API keys',
  50102: 'Request timestamp expired — server clock skew',
  50110: "IP not allowed by the API key's whitelist",
  50011: 'Rate limited by OKX — retry shortly',
  51008: 'Insufficient balance',
  51010: 'Account mode does not allow this — enable derivatives trading in OKX account settings',
  51000: 'Parameter error — check symbol and size',
  51400: 'Order does not exist or is already filled/cancelled',
  51503: 'Order does not exist or is already filled/cancelled',
};

function okxErrorMessage(code, rawMsg) {
  const n = parseInt(code, 10);
  const msg = isNaN(n) ? undefined : OKX_ERRORS[n];
  if (msg) return msg;
  const tail = rawMsg ? ': ' + rawMsg : '';
  return 'OKX error ' + code + tail;
}

// BASE qty → CONTRACTS string (qty ÷ ctVal, quantized 1e-8 half-even,
// integral collapse) — okx_contracts parity.
function okxContracts(qty, ctVal) {
  if (!ctVal) return String(qty);
  const cv = decNorm(ctVal);
  if (cv.digits === 0n || cv.neg) return String(qty);
  const q = decNorm(qty);
  const num = (q.neg ? -1n : 1n) * q.digits * (10n ** BigInt(8 + cv.scale));
  const den = cv.digits * (10n ** BigInt(q.scale));
  let n = divHalfEven(num < 0n ? -num : num, den);
  return decFmt(q.neg, n, 8);
}

function okxClOrdId(clOrdID) {
  return String(clOrdID == null ? '' : clOrdID).replace(/[^A-Za-z0-9]/g, '').slice(0, 32);
}

function okxOrderBody(market, symbol, side, ordType, qty, price, clOrdID, flags) {
  const f = flags || {};
  const sideL = String(side).toLowerCase() === 'buy' ? 'buy' : 'sell';
  const t = String(ordType).toLowerCase();
  const body = {
    instId: String(symbol),
    tdMode: market === 'spot' ? 'cash' : 'cross',
    side: sideL,
    ordType: (t === 'limit' || t === 'stop_limit') ? 'limit' : 'market',
    clOrdId: okxClOrdId(clOrdID),
  };
  if (market === 'spot') {
    body.sz = String(qty);
    if (body.ordType === 'market') {
      body.tgtCcy = sideL === 'buy' ? 'quote_ccy' : 'base_ccy';
    }
  } else {
    body.posSide = 'net';
    body.sz = okxContracts(qty, f.ctVal);
    if (f.reduceOnly) body.reduceOnly = true;
  }
  if (body.ordType === 'limit') body.px = String(price);
  return body;
}

function okxAlgoBody(symbol, side, ordType, qty, price, trigger, clOrdID, flags) {
  const f = flags || {};
  const sideL = String(side).toLowerCase() === 'buy' ? 'buy' : 'sell';
  const t = String(ordType).toLowerCase();
  const body = {
    instId: String(symbol), tdMode: 'cross', posSide: 'net',
    side: sideL, sz: okxContracts(qty, f.ctVal),
    algoClOrdId: okxClOrdId(clOrdID),
  };
  if (f.closeOnTrigger) {
    body.ordType = 'conditional';
    body.reduceOnly = true;
    const pre = t === 'tp_market' ? 'tp' : 'sl';
    body[pre + 'TriggerPx'] = String(trigger);
    body[pre + 'TriggerPxType'] = 'mark';
    body[pre + 'OrdPx'] = '-1';
  } else {
    body.ordType = 'trigger';
    body.triggerPx = String(trigger);
    body.triggerPxType = 'mark';
    body.orderPx = t === 'stop_limit' ? String(price) : '-1';
    if (f.reduceOnly) body.reduceOnly = true;
  }
  return body;
}

// CONTRACTS → BASE qty (× ctVal) — okx_base_qty parity (spot ctVal null passes).
function okxBaseQty(sz, ctVal) {
  const v = bnNum(sz);
  if (v == null) return null;
  if (!ctVal) return v;
  try {
    const a = decNorm(v), b = decNorm(ctVal);
    return decFmt(a.neg !== b.neg, a.digits * b.digits, a.scale + b.scale);
  } catch (e) { return v; }
}

function okxPositionRows(data, ctMap) {
  const rows = [];
  for (const p of ((data || {}).data) || []) {
    try {
      const pos = bnNum((p || {}).pos) || '0';
      if (Number(pos) === 0) continue;
      const neg = pos.startsWith('-');
      const sym = String(p.instId || '');
      rows.push({
        symbol: p.instId,
        side: neg ? 'Sell' : 'Buy',
        size: okxBaseQty(neg ? pos.slice(1) : pos, (ctMap || {})[sym]),
        mark: bnNum(p.markPx),
      });
    } catch (e) { /* skip */ }
  }
  return rows;
}

function okxCancelGone(errText) {
  const s = String(errText || '').toLowerCase();
  if (!s) return false;
  for (const needle of ['already cancelled', 'already canceled', 'already filled',
                        'does not exist', 'order not found', '51400', '51603']) {
    if (s.indexOf(needle) >= 0) return true;
  }
  return false;
}

// --- Gate pure builders ---------------------------------------------------------
function gateBodyHash(body) {
  return crypto.createHash('sha512').update(String(body || ''), 'utf8').digest('hex');
}

function gateSign(secret, method, path, query, body, ts) {
  const msg = [String(method).toUpperCase(), String(path), String(query || ''),
               gateBodyHash(body), String(ts)].join('\n');
  return crypto.createHmac('sha512', String(secret)).update(msg, 'utf8').digest('hex');
}
// #2153 Gate private WS per-subscribe auth (engine gate_ws_sign twin):
// HMAC-SHA512 hex over 'channel=<ch>&event=<ev>&time=<t>'.
function gateWsSign(secret, channel, event, t) {
  return crypto.createHmac('sha512', String(secret))
    .update('channel=' + String(channel) + '&event=' + String(event) + '&time=' + String(t), 'utf8')
    .digest('hex');
}

const GATE_ERRORS = {
  INVALID_KEY: 'Invalid API key',
  INVALID_SIGNATURE: 'Invalid request signature — re-enter your API keys',
  INVALID_CREDENTIALS: 'Invalid API credentials — re-enter your API keys',
  REQUEST_EXPIRED: 'Request timestamp expired — server clock skew',
  IP_FORBIDDEN: "IP not allowed by the API key's whitelist",
  FORBIDDEN: 'API key lacks permission for this action',
  READ_ONLY: 'API key is read-only — enable trading permission',
  TOO_MANY_REQUESTS: 'Rate limited by Gate — retry shortly',
  BALANCE_NOT_ENOUGH: 'Insufficient balance',
  MARGIN_BALANCE_NOT_ENOUGH: 'Insufficient margin balance',
  ORDER_NOT_FOUND: 'Order does not exist or is already filled/cancelled',
  AUTO_ORDER_NOT_FOUND: 'Order does not exist or is already filled/cancelled',
  ORDER_FINISHED: 'Order does not exist or is already filled/cancelled',
  ORDER_CLOSED: 'Order does not exist or is already filled/cancelled',
  INVALID_PARAM_VALUE: 'Parameter error — check symbol and size',
  INVALID_PRECISION: 'Price/size precision not accepted by Gate',
  QUANTITY_NOT_ENOUGH: 'Size below the venue minimum',
  POSITION_NOT_FOUND: 'Position not found',
  USER_NOT_FOUND: 'No Gate futures account — open one on Gate first',
  CONTRACT_NOT_FOUND: 'Unknown contract',
  RISK_LIMIT_EXCEEDED: 'Risk limit exceeded — lower leverage/size',
  LEVERAGE_TOO_HIGH: 'Leverage above the contract maximum',
};

function gateErrorMessage(label, rawMsg) {
  const lbl = String(label == null ? '' : label).trim();
  const msg = GATE_ERRORS[lbl.toUpperCase()];
  if (msg) return msg;
  const tail = rawMsg ? ': ' + rawMsg : '';
  return 'Gate error ' + (lbl || 'unknown') + tail;
}

// BASE qty → INTEGER CONTRACTS string (÷ quanto_multiplier, floor toward
// zero after a 1e-8 half-even quantize) — gate_contracts parity.
function gateContracts(qty, multiplier) {
  if (!multiplier) return String(qty);
  const mult = decNorm(multiplier);
  if (mult.digits === 0n || mult.neg) return String(qty);
  const q = decNorm(qty);
  const num = q.digits * (10n ** BigInt(8 + mult.scale));
  const den = mult.digits * (10n ** BigInt(q.scale));
  const n8 = divHalfEven(num, den);       // quantized at scale 8, unsigned
  const whole = n8 / (10n ** 8n);         // truncate toward zero
  return (q.neg ? '-' : '') + whole.toString();
}

function gateText(clOrdID) {
  const s = String(clOrdID == null ? '' : clOrdID).replace(/[^0-9A-Za-z_.-]/g, '');
  return 't-' + s.slice(0, 28);
}

function gateOrderBody(market, symbol, side, ordType, qty, price, clOrdID, flags) {
  const f = flags || {};
  const sideL = String(side).toLowerCase() === 'buy' ? 'buy' : 'sell';
  const t = String(ordType).toLowerCase();
  const isLimit = t === 'limit' || t === 'stop_limit';
  if (market === 'spot') {
    const body = {
      currency_pair: String(symbol),
      side: sideL,
      type: isLimit ? 'limit' : 'market',
      account: 'spot',
      amount: String(qty),
      text: gateText(clOrdID),
    };
    if (isLimit) {
      body.price = String(price);
      body.time_in_force = 'gtc';
    } else {
      body.time_in_force = 'ioc';
    }
    return body;
  }
  const size = truncInt(gateContracts(qty, f.multiplier));
  const body = {
    contract: String(symbol),
    size: sideL === 'buy' ? size : -size,
    price: isLimit ? String(price) : '0',
    tif: isLimit ? 'gtc' : 'ioc',
    text: gateText(clOrdID),
  };
  if (f.reduceOnly) body.reduce_only = true;
  return body;
}

function gatePoRule(side, ordType) {
  const isTp = String(ordType).toLowerCase() === 'tp_market';
  const buy = String(side).toLowerCase() === 'buy';
  return buy !== isTp ? 1 : 2;
}

function gatePoBody(symbol, side, ordType, qty, price, trigger, clOrdID, flags) {
  const f = flags || {};
  const sideL = String(side).toLowerCase() === 'buy' ? 'buy' : 'sell';
  const t = String(ordType).toLowerCase();
  const n = truncInt(gateContracts(qty, f.multiplier));
  const initial = {
    contract: String(symbol),
    size: sideL === 'buy' ? n : -n,
    price: t === 'stop_limit' ? String(price) : '0',
    tif: t === 'stop_limit' ? 'gtc' : 'ioc',
    text: gateText(clOrdID),
  };
  if (f.reduceOnly || f.closeOnTrigger) initial.reduce_only = true;
  return {
    initial: initial,
    trigger: {
      strategy_type: 0,
      price_type: 1,
      price: String(trigger),
      rule: gatePoRule(sideL, t),
    },
  };
}

// |CONTRACTS| × quanto_multiplier → BASE qty (gate_base_qty parity).
function gateBaseQty(size, multiplier) {
  const v = bnNum(size);
  if (v == null) return null;
  const abs = v.startsWith('-') ? v.slice(1) : v;
  if (!multiplier) return abs;
  try {
    const a = decNorm(abs), b = decNorm(multiplier);
    return decFmt(false, a.digits * b.digits, a.scale + b.scale);
  } catch (e) { return abs; }
}

function gatePositionRows(data, multMap) {
  const rows = [];
  for (const p of Array.isArray(data) ? data : []) {
    try {
      const size = bnNum((p || {}).size) || '0';
      if (Number(size) === 0) continue;
      const sym = String(p.contract || '');
      rows.push({
        symbol: p.contract,
        side: size.startsWith('-') ? 'Sell' : 'Buy',
        size: gateBaseQty(size, (multMap || {})[sym]),
        mark: bnNum(p.mark_price),
      });
    } catch (e) { /* skip */ }
  }
  return rows;
}

function gateCancelGone(msg) {
  const t = String(msg || '').toLowerCase();
  return (t.indexOf('not found') >= 0 || t.indexOf('does not exist') >= 0
          || t.indexOf('already') >= 0 || t.indexOf('finished') >= 0
          || t.indexOf('not exist') >= 0);
}

// --- Bitget pure builders --------------------------------------------------------
function bitgetSign(secret, ts, method, path, body) {
  const msg = String(ts) + String(method).toUpperCase() + String(path) + String(body || '');
  return crypto.createHmac('sha256', String(secret)).update(msg, 'utf8').digest('base64');
}
// #2247 private-WS login signature (engine bitget_ws_login_sig twin). Same
// HMAC-SHA256/base64 primitive as the REST signer over a FIXED
// '<ts>GET/user/verify' message — but the timestamp is epoch SECONDS here,
// while every REST header stamps MILLISECONDS. Feeding ms returns error
// 30005 (login failure) with no hint about which field is wrong.
function bitgetWsLoginSig(secret, tsSec) {
  return bitgetSign(secret, tsSec, 'GET', '/user/verify', '');
}

const BITGET_ERRORS = {
  40006: 'Invalid API key',
  40009: 'Invalid request signature — re-enter your API keys',
  40012: 'Invalid passphrase — re-enter your API keys',
  40008: 'Request timestamp expired — server clock skew',
  40018: "IP not allowed by the API key's whitelist",
  429: 'Rate limited by Bitget — retry shortly',
  43012: 'Insufficient balance',
  40754: 'Insufficient balance',
  43001: 'Order does not exist or is already filled/cancelled',
  40768: 'Order does not exist or is already filled/cancelled',
};

function bitgetErrorMessage(code, rawMsg) {
  const n = parseInt(code, 10);
  const msg = isNaN(n) ? undefined : BITGET_ERRORS[n];
  if (msg) return msg;
  const tail = rawMsg ? ': ' + rawMsg : '';
  return 'Bitget error ' + code + tail;
}

function bitgetClOrdId(clOrdID) {
  return String(clOrdID == null ? '' : clOrdID).replace(/[^A-Za-z0-9]/g, '').slice(0, 32);
}

function bitgetOrderBody(market, symbol, side, ordType, qty, price, clOrdID, flags) {
  const f = flags || {};
  const sideL = String(side).toLowerCase() === 'buy' ? 'buy' : 'sell';
  const t = String(ordType).toLowerCase();
  const isLimit = t === 'limit' || t === 'stop_limit';
  const body = {
    symbol: String(symbol),
    side: sideL,
    orderType: isLimit ? 'limit' : 'market',
    size: String(qty),
    clientOid: bitgetClOrdId(clOrdID),
  };
  if (isLimit) {
    body.price = String(price);
    body.force = 'gtc';
  }
  if (market === 'futures') {
    body.productType = BITGET_PRODUCT_TYPE;
    body.marginMode = 'crossed';
    body.marginCoin = 'USDT';
    if (f.reduceOnly) body.reduceOnly = 'YES';
  }
  return body;
}

function bitgetPlanBody(symbol, side, ordType, qty, price, trigger, clOrdID, flags) {
  const f = flags || {};
  const sideL = String(side).toLowerCase() === 'buy' ? 'buy' : 'sell';
  const t = String(ordType).toLowerCase();
  if (f.closeOnTrigger) {
    return {
      symbol: String(symbol),
      productType: BITGET_PRODUCT_TYPE,
      marginMode: 'crossed',
      marginCoin: 'USDT',
      planType: t === 'tp_market' ? 'profit_plan' : 'loss_plan',
      triggerPrice: String(trigger),
      triggerType: 'mark_price',
      holdSide: sideL === 'sell' ? 'buy' : 'sell',
      size: String(qty),
      executePrice: '0',
      clientOid: bitgetClOrdId(clOrdID),
    };
  }
  const body = {
    symbol: String(symbol),
    productType: BITGET_PRODUCT_TYPE,
    marginMode: 'crossed',
    marginCoin: 'USDT',
    planType: 'normal_plan',
    side: sideL,
    orderType: t === 'stop_limit' ? 'limit' : 'market',
    size: String(qty),
    triggerPrice: String(trigger),
    triggerType: 'mark_price',
    clientOid: bitgetClOrdId(clOrdID),
  };
  if (t === 'stop_limit') body.price = String(price);
  if (f.reduceOnly) body.reduceOnly = 'YES';
  return body;
}

function bitgetPositionRows(data) {
  const rows = [];
  for (const p of ((data || {}).data) || []) {
    try {
      const total = bnNum(p.total) || bnNum(p.size) || '0';
      if (Number(total) === 0) continue;
      const hold = String(p.holdSide || '').toLowerCase();
      rows.push({
        symbol: p.symbol || p.instId,
        side: (hold === 'long' || hold === 'buy') ? 'Buy' : 'Sell',
        size: total,
        mark: bnNum(p.markPrice),
      });
    } catch (e) { /* skip */ }
  }
  return rows;
}

function bitgetCancelGone(errText) {
  const s = String(errText || '').toLowerCase();
  if (!s) return false;
  for (const needle of ['already cancelled', 'already canceled', 'already filled',
                        'does not exist', 'not exist', 'order not found',
                        '43001', '40768', '40923']) {
    if (s.indexOf(needle) >= 0) return true;
  }
  return false;
}

// --- KuCoin pure builders (parity with terminal_engine.py) -----------------
function kcSign(secret, tsMs, method, path, body) {
  const msg = String(tsMs) + String(method).toUpperCase() + String(path) + String(body || '');
  return crypto.createHmac('sha256', String(secret)).update(msg, 'utf8').digest('base64');
}

// v2/v3 keys: the KC-API-PASSPHRASE header value is itself HMAC-signed.
function kcPassphraseSig(secret, passphrase) {
  return crypto.createHmac('sha256', String(secret)).update(String(passphrase), 'utf8').digest('base64');
}

const KUCOIN_ERRORS = {
  400003: 'Invalid API key',
  400004: 'Invalid passphrase — re-enter your API keys',
  400005: 'Invalid request signature — re-enter your API keys',
  400002: 'Request timestamp expired — server clock skew',
  400006: "IP not allowed by the API key's whitelist",
  400007: 'API key lacks permission for this action',
  411100: 'Account is frozen — contact KuCoin support',
  429000: 'Rate limited by KuCoin — retry shortly',
  200004: 'Insufficient balance',
  300000: 'Insufficient balance',
  400100: 'Order rejected — check parameters/balance',
  404000: 'Order does not exist or is already filled/cancelled',
};

function kcErrorMessage(code, rawMsg) {
  const n = parseInt(code, 10);
  const msg = isNaN(n) ? undefined : KUCOIN_ERRORS[n];
  if (msg) return msg;
  const tail = rawMsg ? ': ' + rawMsg : '';
  return 'KuCoin error ' + code + tail;
}

function kcClOrdId(clOrdID) {
  return String(clOrdID == null ? '' : clOrdID).replace(/[^A-Za-z0-9]/g, '').slice(0, 32);
}

// BASE qty → INTEGER contracts (qty ÷ multiplier, quantize 1e-8 half-even,
// then truncate toward zero) — kc_contracts parity.
function kcContracts(qty, multiplier) {
  if (!multiplier) return String(qty);
  let mult;
  try { mult = decNorm(multiplier); } catch (e) { return String(qty); }
  if (mult.digits === 0n || mult.neg) return String(qty);
  let q;
  try { q = decNorm(qty); } catch (e) { return String(qty); }
  const num = q.digits * (10n ** BigInt(8 + mult.scale));
  const den = mult.digits * (10n ** BigInt(q.scale));
  const n8 = divHalfEven(num, den);       // quantized at scale 8, unsigned
  const whole = n8 / (10n ** 8n);         // truncate toward zero
  return (q.neg ? '-' : '') + whole.toString();
}

// CONTRACTS → BASE qty (× multiplier) — kc_base_qty parity (spot mult null passes).
function kcBaseQty(size, multiplier) {
  const v = bnNum(size);
  if (v == null) return null;
  if (!multiplier) return v;
  try {
    const a = decNorm(v), b = decNorm(multiplier);
    return decFmt(a.neg !== b.neg, a.digits * b.digits, a.scale + b.scale);
  } catch (e) { return v; }
}

function kcSpotOrderBody(symbol, side, ordType, qty, price, clOrdID) {
  const sideL = String(side).toLowerCase() === 'buy' ? 'buy' : 'sell';
  const isLimit = String(ordType).toLowerCase() === 'limit';
  const body = {
    clientOid: kcClOrdId(clOrdID),
    symbol: String(symbol),
    side: sideL,
    type: isLimit ? 'limit' : 'market',
  };
  if (isLimit) {
    body.price = String(price);
    body.size = String(qty);
  } else if (sideL === 'buy') {
    body.funds = String(qty);      // market BUY qty = USDT amount
  } else {
    body.size = String(qty);
  }
  return body;
}

function kcFutOrderBody(symbol, side, ordType, contracts, price, clOrdID, leverage, flags) {
  const f = flags || {};
  const sideL = String(side).toLowerCase() === 'buy' ? 'buy' : 'sell';
  const t = String(ordType).toLowerCase();
  const isStop = t === 'stop' || t === 'stop_limit' || t === 'tp_market';
  const isLimit = t === 'limit' || t === 'stop_limit';
  const body = {
    clientOid: kcClOrdId(clOrdID),
    symbol: String(symbol),
    side: sideL,
    type: isLimit ? 'limit' : 'market',
    leverage: String(leverage),
    size: String(contracts),
    marginMode: 'CROSS',
  };
  if (isLimit) body.price = String(price);
  if (f.reduceOnly) body.reduceOnly = true;
  if (isStop) {
    body.stop = (f.triggerDir === 'down' || f.triggerDir === 'up') ? f.triggerDir : 'down';
    body.stopPrice = String(f.trigger);
    body.stopPriceType = 'MP';
  }
  return body;
}

// 'down' fires when mark falls to the trigger, 'up' when it rises.
function kcStopDir(side, trigger, mid) {
  try {
    if (trigger != null && mid != null) {
      const a = decNorm(trigger), b = decNorm(mid);
      const av = (a.neg ? -1n : 1n) * a.digits * (10n ** BigInt(b.scale));
      const bv = (b.neg ? -1n : 1n) * b.digits * (10n ** BigInt(a.scale));
      return av >= bv ? 'up' : 'down';
    }
  } catch (e) { /* fall through */ }
  return String(side).toLowerCase() === 'sell' ? 'down' : 'up';
}

function kcPositionRows(data, multMap) {
  const rows = [];
  for (const p of (((data || {}).data) || [])) {
    try {
      const q = bnNum(p.currentQty);
      if (q == null || Number(q) === 0) continue;
      const neg = String(q).indexOf('-') === 0;
      const abs = neg ? String(q).slice(1) : String(q);
      rows.push({
        symbol: p.symbol,
        side: neg ? 'Sell' : 'Buy',
        size: kcBaseQty(abs, (multMap || {})[String(p.symbol || '')]),
        mark: bnNum(p.markPrice),
      });
    } catch (e) { /* skip */ }
  }
  return rows;
}

function kucoinCancelGone(errText) {
  const s = String(errText || '').toLowerCase();
  if (!s) return false;
  for (const needle of ['already cancelled', 'already canceled', 'already filled',
                        'does not exist', 'not exist', 'order not found',
                        '404000', '100004', 'http 404']) {
    if (s.indexOf(needle) >= 0) return true;
  }
  return false;
}

// A 2xx response whose body failed JSON.parse must surface as an HONEST
// error message, NEVER ok:true/data:null — the httpJson byte cap can
// truncate huge bodies (symbol-less /fapi/v2/positionRisk measured 200KB+),
// and a data:null "success" once made futures close report "Position not
// found". Returns the error message, or null when the parse succeeded.
// (>=400 statuses are handled by the callers' own HTTP-error branches.)
function unreadableBodyMsg(venue, status, parsed) {
  if (parsed !== null && parsed !== undefined) return null;
  return String(venue) + ' returned an unreadable response (HTTP ' + status + ')';
}

// --- BitMEX pure builders (parity with terminal_engine.py) -----------------
function bmxSign(secret, verb, path, expires, body) {
  const msg = String(verb).toUpperCase() + String(path) + String(expires) + String(body || '');
  return crypto.createHmac('sha256', String(secret)).update(msg, 'utf8').digest('hex');
}

function bmxExpires(nowSec) {
  const t = nowSec == null ? Date.now() / 1000 : Number(nowSec);
  return Math.trunc(t) + 30;
}

function bmxClOrdId(clOrdID) {
  return String(clOrdID == null ? '' : clOrdID).replace(/[^A-Za-z0-9]/g, '').slice(0, 36);
}

// BASE qty → integer CONTRACTS (qty × u2pm quantize 1e-8 half-even →
// truncate toward zero → floor to lotSize multiple) — bmx_contracts parity.
function bmxContracts(qty, u2pm, lotSize) {
  if (!u2pm) return String(qty);
  let m, q;
  try { m = decNorm(u2pm); q = decNorm(qty); } catch (e) { return String(qty); }
  if (m.digits === 0n || m.neg) return String(qty);
  const prod = q.digits * m.digits;          // scale q.scale + m.scale
  const sc = q.scale + m.scale;
  const n8 = sc <= 8 ? prod * (10n ** BigInt(8 - sc))
                     : divHalfEven(prod, 10n ** BigInt(sc - 8));
  let n = n8 / (10n ** 8n);                  // truncate toward zero (unsigned)
  let lot = 0n;
  if (lotSize) {
    try {
      const l = decNorm(lotSize);
      if (!l.neg) lot = l.digits / (10n ** BigInt(l.scale));
    } catch (e) { lot = 0n; }
  }
  if (lot > 0n) n = (n / lot) * lot;
  return (q.neg ? '-' : '') + n.toString();
}

// CONTRACTS → BASE qty (÷ u2pm) — exact for the power-of-10 multipliers
// BitMEX uses; half-even at scale+28 otherwise (Decimal-context family).
function bmxBaseQty(contracts, u2pm) {
  const v = bnNum(contracts);
  if (v == null) return null;
  if (!u2pm) return v;
  try {
    const a = decNorm(v), b = decNorm(u2pm);
    if (b.digits === 0n || b.neg) return v;
    const num = a.digits * (10n ** 28n) * (10n ** BigInt(b.scale));
    return decFmt(a.neg, divHalfEven(num, b.digits), a.scale + 28);
  } catch (e) { return v; }
}

// Python float repr — json.dumps renders BitMEX price/stopPx as repr(float)
// (70000 → '70000.0', 0.00001234 → '1.234e-05'). Byte parity is mandatory:
// the signature covers the exact body string.
function pyFloat(v) {
  const x = Number(v);
  if (!isFinite(x)) throw new Error('unrepresentable float: ' + v);
  if (x === 0) return Object.is(x, -0) ? '-0.0' : '0.0';
  const neg = x < 0;
  const es = Math.abs(x).toExponential();    // shortest round-trip digits
  const m = /^(\d)(?:\.(\d+))?e([+-]\d+)$/.exec(es);
  if (!m) throw new Error('unrepresentable float: ' + v);
  const digits = m[1] + (m[2] || '');
  const exp = parseInt(m[3], 10);
  let out;
  if (exp < -4 || exp >= 16) {
    const mant = m[1] + (m[2] ? '.' + m[2] : '');
    let ea = String(Math.abs(exp));
    if (ea.length < 2) ea = '0' + ea;
    out = mant + 'e' + (exp < 0 ? '-' : '+') + ea;
  } else if (exp >= 0) {
    const ip = digits.slice(0, exp + 1).padEnd(exp + 1, '0');
    const fp = digits.slice(exp + 1);
    out = ip + '.' + (fp || '0');
  } else {
    out = '0.' + '0'.repeat(-exp - 1) + digits;
  }
  return (neg ? '-' : '') + out;
}

// Returns the exact JSON STRING (json.dumps separators-(",",":") parity —
// price/stopPx are Python floats, orderQty a Python int).
function bmxOrderBody(symbol, side, ordType, contracts, price, clOrdID, flags) {
  const f = flags || {};
  const t = String(ordType).toLowerCase();
  const parts = [];
  const add = (k, raw) => parts.push(JSON.stringify(k) + ':' + raw);
  add('symbol', JSON.stringify(String(symbol)));
  add('side', JSON.stringify(String(side).toLowerCase() === 'buy' ? 'Buy' : 'Sell'));
  add('orderQty', String(truncInt(String(contracts))));
  add('clOrdID', JSON.stringify(bmxClOrdId(clOrdID)));
  const execInst = [];
  if (t === 'limit') {
    add('ordType', '"Limit"');
    add('price', pyFloat(price));
  } else if (t === 'market') {
    add('ordType', '"Market"');
  } else if (t === 'stop') {
    add('ordType', '"Stop"');
    add('stopPx', pyFloat(f.trigger));
    execInst.push('MarkPrice');
  } else if (t === 'stop_limit') {
    add('ordType', '"StopLimit"');
    add('stopPx', pyFloat(f.trigger));
    add('price', pyFloat(price));
    execInst.push('MarkPrice');
  } else if (t === 'tp_market') {
    add('ordType', '"MarketIfTouched"');
    add('stopPx', pyFloat(f.trigger));
    execInst.push('MarkPrice');
  }
  if (f.reduceOnly || f.closeOnTrigger) execInst.push('ReduceOnly');
  if (execInst.length) add('execInst', JSON.stringify(execInst.join(',')));
  return '{' + parts.join(',') + '}';
}

function bmxPositionRows(data, multMap) {
  const rows = [];
  for (const p of (Array.isArray(data) ? data : [])) {
    try {
      const q = bnNum(p.currentQty);
      if (q == null || Number(q) === 0) continue;
      const neg = String(q).indexOf('-') === 0;
      const abs = neg ? String(q).slice(1) : String(q);
      rows.push({
        symbol: p.symbol,
        side: neg ? 'Sell' : 'Buy',
        size: bmxBaseQty(abs, (multMap || {})[String(p.symbol || '')]),
        mark: bnNum(p.markPrice),
      });
    } catch (e) { /* skip */ }
  }
  return rows;
}

function bitmexCancelGone(errText) {
  const s = String(errText || '').toLowerCase();
  if (!s) return false;
  for (const needle of ['already', 'not found', 'unable to cancel',
                        'invalid orderid', 'invalid ordstatus']) {
    if (s.indexOf(needle) >= 0) return true;
  }
  return false;
}

// --- MEXC (venue #11 — spot Binance-family + contract.mexc.com futures) ----
// Pure builders: golden-vector parity with terminal_engine.py (mexc_* fns).
const MEXC_SPOT_HOST = 'api.mexc.com';
const MEXC_FUT_HOST = 'contract.mexc.com';
const MX_NATIVE_LEVERAGE = '10';   // engine MX_DEFAULT_LEVERAGE parity

// Spot signature: hex(HMAC-SHA256(secret, query)) — exact Binance recipe.
function mexcSpotSign(secret, query) {
  return crypto.createHmac('sha256', String(secret)).update(String(query), 'utf8').digest('hex');
}
// Futures signature: hex(HMAC-SHA256(secret, accessKey + ts + paramString)).
function mexcFutSign(accessKey, secret, tsMs, paramStr) {
  const msg = String(accessKey) + String(tsMs) + String(paramStr == null ? '' : paramStr);
  return crypto.createHmac('sha256', String(secret)).update(msg, 'utf8').digest('hex');
}
// GET/DELETE paramString: key=value joined with '&', keys SORTED (dictionary
// order) — values verbatim (no URL-encoding) — mexc_fut_param_str parity.
function mexcFutParamStr(params) {
  if (!params) return '';
  const keys = Object.keys(params).sort();
  return keys.map((k) => k + '=' + params[k]).join('&');
}

// Cryptic MEXC codes → clear panel messages (engine MEXC_ERRORS parity).
const MEXC_ERRORS = {
  700002: 'Invalid request signature — re-enter your API keys',
  700007: "IP not allowed by the API key's whitelist",
  10072: 'Invalid API key',
  700003: 'Request timestamp expired — server clock skew',
  10007: 'This spot symbol is API-restricted on MEXC — connect your ' +
         'MEXC UID + web session in the key settings to trade it',
  30016: 'Trading is suspended for this symbol',
  30004: 'Insufficient balance',
  700013: 'Invalid API key permissions',
  401: 'Invalid API key or signature — re-enter your API keys',
  602: 'Invalid request signature — re-enter your API keys',
  1002: 'Contract not activated — open a futures account on MEXC first',
  2005: 'Insufficient balance',
  2011: 'Order does not exist or is already filled/cancelled',
  510: 'Rate limited by MEXC — retry shortly',
};
function mexcErrorMessage(code, rawMsg) {
  const c = parseInt(code, 10);
  const msg = isFinite(c) ? MEXC_ERRORS[c] : null;
  if (msg) return msg;
  const tail = rawMsg ? ': ' + rawMsg : '';
  return 'MEXC error ' + code + tail;
}
function mexcIsRestrictedErr(code) {
  return parseInt(code, 10) === 10007;
}
// MEXC's 'quantity scale is invalid' rejection (the real market-order scale
// is unpublished and can be coarser than every exchangeInfo precision
// field) — mexc_is_qty_scale_err parity.
function mexcIsQtyScaleErr(msg) {
  return String(msg == null ? '' : msg).toLowerCase()
    .indexOf('quantity scale is invalid') >= 0;
}
// Decimal scale (# significant decimals) of a plain qty string —
// mexc_qty_scale parity ("0.0050" → 3, "4.73" → 2, "50"/"junk" → 0).
function mexcQtyScale(q) {
  const s = String(q == null ? '' : q).trim();
  if (!/^\d+(\.\d+)?$/.test(s)) return 0;
  const i = s.indexOf('.');
  if (i < 0) return 0;
  return s.slice(i + 1).replace(/0+$/, '').length;
}
// Floor a qty string to `sc` decimals (string truncation — never rounds
// up), trailing zeros stripped — mexc_qty_floor_scale parity ("4.739",2 →
// "4.73"; "0.9",0 → "0"; bad input / negative scale → null).
function mexcQtyFloorScale(q, sc) {
  const s = String(q == null ? '' : q).trim();
  const n = Math.floor(Number(sc));
  if (!/^\d+(\.\d+)?$/.test(s) || !isFinite(n) || n < 0) return null;
  const i = s.indexOf('.');
  let out = i < 0 ? s : (n > 0 ? s.slice(0, i + 1 + n) : s.slice(0, i));
  if (out.indexOf('.') >= 0) out = out.replace(/0+$/, '').replace(/\.$/, '');
  return out === '' ? '0' : out;
}

// Client order id: alphanumeric strip + 32-char truncate — mexc_clordid parity.
function mexcClOrdId(clOrdID) {
  return String(clOrdID == null ? '' : clOrdID).replace(/[^A-Za-z0-9]/g, '').slice(0, 32);
}
// One-way futures side → MEXC 1-4 code (1 open long / 2 close short /
// 3 open short / 4 close long) — mexc_fut_side parity.
function mexcFutSide(side, reduceOnly) {
  const isBuy = String(side).toLowerCase() === 'buy';
  if (reduceOnly) return isBuy ? 2 : 4;
  return isBuy ? 1 : 3;
}

// BASE qty → CONTRACTS string: (qty ÷ contractSize) quantized half-even at
// scale 8, floored to volUnit multiples — mexc_contracts parity.
function mexcContracts(qty, ctVal, volStep) {
  if (!ctVal) return String(qty);
  let cv, q;
  try { cv = decNorm(ctVal); q = decNorm(qty); } catch (e) { return String(qty); }
  if (cv.digits === 0n || cv.neg) return String(qty);
  const num = q.digits * (10n ** BigInt(8 + cv.scale));
  const den = cv.digits * (10n ** BigInt(q.scale));
  let n8 = divHalfEven(num, den);            // unsigned, scale 8
  let sD = null;
  if (volStep) { try { sD = decNorm(volStep); } catch (e) { sD = null; } }
  if (!sD || sD.neg || sD.digits === 0n) sD = { neg: false, digits: 1n, scale: 0 };
  const step8 = sD.scale <= 8 ? sD.digits * (10n ** BigInt(8 - sD.scale))
                              : sD.digits / (10n ** BigInt(sD.scale - 8));
  if (step8 > 0n) n8 = (n8 / step8) * step8;
  return decFmt(q.neg, n8, 8);
}
// CONTRACTS (or base when ctVal falsy) → BASE qty — mexc_base_qty parity.
function mexcBaseQty(vol, ctVal) {
  const v = bnNum(vol);
  if (v == null) return null;
  if (!ctVal) return v;
  try {
    const a = decNorm(v), b = decNorm(ctVal);
    return decFmt(a.neg !== b.neg, a.digits * b.digits, a.scale + b.scale);
  } catch (e) { return v; }
}

// Deterministic query params (ordered pairs) for POST /api/v3/order —
// mexc_spot_order_params parity (market BUY sends quoteOrderQty = USDT).
function mexcSpotOrderParams(symbol, side, ordType, qty, price, clOrdID) {
  const sideU = String(side).toLowerCase() === 'buy' ? 'BUY' : 'SELL';
  const isLimit = String(ordType).toLowerCase() === 'limit';
  const p = [
    ['symbol', String(symbol)],
    ['side', sideU],
    ['type', isLimit ? 'LIMIT' : 'MARKET'],
    ['newClientOrderId', mexcClOrdId(clOrdID)],
  ];
  if (isLimit) {
    p.push(['price', String(price)]);
    p.push(['quantity', String(qty)]);
  } else if (sideU === 'BUY') {
    p.push(['quoteOrderQty', String(qty)]);
  } else {
    p.push(['quantity', String(qty)]);
  }
  return p;
}

// Deterministic body for POST /api/v1/private/order/submit —
// mexc_fut_order_body parity (key insertion order matches json.dumps).
function mexcFutOrderBody(symbol, side, ordType, contracts, price, clOrdID, flags) {
  const f = flags || {};
  const isLimit = ['limit', 'stop_limit'].indexOf(String(ordType).toLowerCase()) >= 0;
  const body = {
    symbol: String(symbol),
    vol: String(contracts),
    side: mexcFutSide(side, !!f.reduceOnly),
    type: isLimit ? 1 : 5,
    openType: 2,
    externalOid: mexcClOrdId(clOrdID),
  };
  if (isLimit) body.price = String(price);
  if (f.leverage) body.leverage = String(f.leverage);
  return body;
}

// Plan-order trend (trigger comparator) — mexc_plan_trend parity.
function mexcPlanTrend(side, ordType) {
  const isBuy = String(side).toLowerCase() === 'buy';
  if (String(ordType).toLowerCase() === 'tp_market') return isBuy ? 2 : 1;
  return isBuy ? 1 : 2;
}
// Deterministic body for POST /api/v1/private/planorder/place —
// mexc_plan_body parity (triggerType 2 = fair/mark for SL/TP).
function mexcPlanBody(symbol, side, ordType, contracts, price, trigger, flags) {
  const f = flags || {};
  const isLimit = String(ordType).toLowerCase() === 'stop_limit';
  const body = {
    symbol: String(symbol),
    vol: String(contracts),
    side: mexcFutSide(side, !!f.reduceOnly),
    openType: 2,
    triggerPrice: String(trigger),
    triggerType: f.triggerType != null ? Math.trunc(Number(f.triggerType)) : 1,
    executeCycle: 3,
    orderType: isLimit ? 1 : 5,
    trend: mexcPlanTrend(side, ordType),
  };
  if (isLimit) body.price = String(price);
  if (f.leverage) body.leverage = String(f.leverage);
  return body;
}

// Futures open_positions rows → common position-row shape —
// mexc_row_from_position parity (holdVol CONTRACTS → BASE via contractSize;
// mark is not in the payload → null, sltpTriggerOk skips the mark check).
function mexcPositionRows(data, ctVal) {
  const rows = [];
  const lst = (data && Array.isArray(data.data)) ? data.data : [];
  for (const p of lst) {
    try {
      const vol = bnNum((p || {}).holdVol);
      if (vol == null || Number(vol) === 0) continue;
      const isLong = parseInt(p.positionType || 1, 10) !== 2;
      rows.push({
        symbol: p.symbol,
        side: isLong ? 'Buy' : 'Sell',
        size: mexcBaseQty(vol.indexOf('-') === 0 ? vol.slice(1) : vol, ctVal),
        mark: null,
        leverage: bnNum(p.leverage),
      });
    } catch (e) { /* skip */ }
  }
  return rows;
}

function mexcCancelGone(errText) {
  const s = String(errText || '').toLowerCase();
  if (!s) return false;
  for (const needle of ['does not exist', 'already', 'not found']) {
    if (s.indexOf(needle) >= 0) return true;
  }
  return false;
}

// --- Kraken pure builders (venue #14 — parity with terminal_engine kr_*) ----
const KRAKEN_SPOT_HOST = 'api.kraken.com';
const KRAKEN_FUT_HOST = 'futures.kraken.com';

// Spot API-Sign: b64(HMAC-SHA512(b64decode(secret), path + SHA256(nonce +
// postdata))) — kr_spot_sign golden parity.
function krSpotSign(secretB64, path, nonce, postdata) {
  const digest = crypto.createHash('sha256')
    .update(String(nonce) + String(postdata), 'utf8').digest();
  return crypto.createHmac('sha512', Buffer.from(String(secretB64), 'base64'))
    .update(Buffer.concat([Buffer.from(String(path), 'utf8'), digest]))
    .digest('base64');
}
// Futures Authent: b64(HMAC-SHA512(b64decode(secret), SHA256(postData +
// nonce + endpointPath))) — endpointPath EXCLUDES /derivatives (kr_fut_sign).
function krFutSign(secretB64, endpointPath, postData, nonce) {
  const digest = crypto.createHash('sha256')
    .update(String(postData) + String(nonce == null ? '' : nonce) + String(endpointPath), 'utf8')
    .digest();
  return crypto.createHmac('sha512', Buffer.from(String(secretB64), 'base64'))
    .update(digest).digest('base64');
}
// Request path → futures signing path (strip /derivatives) — kr_fut_sign_path.
function krFutSignPath(path) {
  const p = String(path || '');
  return p.indexOf('/derivatives') === 0 ? p.slice('/derivatives'.length) : p;
}
// Client id: alnum ≤36 — fits spot cl_ord_id AND futures cliOrdId (kr_clordid).
function krClOrdId(clOrdID) {
  return String(clOrdID || '').replace(/[^A-Za-z0-9]/g, '').slice(0, 36);
}
// Decimal-count → step string ('0'→'1', '2'→'0.01') — kr_dec_step parity.
function krDecStep(d) {
  const n = parseInt(d, 10);
  if (!Number.isFinite(n) || String(n) !== String(d).trim() || n < 0 || n > 18) return null;
  return n === 0 ? '1' : '0.' + '0'.repeat(n - 1) + '1';
}
// Floor a BASE quantity to the instrument step — kr_qty_floor parity.
function krQtyFloor(qty, step) {
  let q, st;
  try { q = decNorm(qty); } catch (e) { return null; }
  if (q.neg && q.digits !== 0n) return null;
  if (step) {
    try { st = decNorm(step); } catch (e) { st = null; }
    if (st && !st.neg && st.digits > 0n) {
      // scale both to a common scale, integer-divide, re-multiply
      const sc = Math.max(q.scale, st.scale);
      const qd = q.digits * 10n ** BigInt(sc - q.scale);
      const sd = st.digits * 10n ** BigInt(sc - st.scale);
      const floored = (qd / sd) * sd;
      return decFmt(false, floored, sc);
    }
  }
  return decFmt(false, q.digits, q.scale);
}
// #1966 pure: /derivatives/api/v3/leveragepreferences envelope → the
// configured leverage for `symbol` (string) or null when no preference row
// exists (Kraken default: cross margin at the contract's max — the PANEL
// resolves that to the spec max, engine #1895 parity).
function krLevPrefPick(data, symbol) {
  const sym = String(symbol || '').toUpperCase();
  for (const p of (((data || {}).leveragePreferences) || [])) {
    if (String((p || {}).symbol || '').toUpperCase() === sym) {
      const v = parseFloat((p || {}).maxLeverage);
      return (isFinite(v) && v > 0) ? String(v) : null;
    }
  }
  return null;
}
// Futures /derivatives/api/v3/sendorder param list — kr_fut_order_params
// parity (stp/take_profit + triggerSignal=mark; stop w/o limitPrice executes
// as market on trigger). Null on an unknown type.
function krFutOrderParams(symbol, side, ordType, qty, price, clOrdID, flags) {
  const f = flags || {};
  const t = String(ordType).toLowerCase();
  const p = [];
  if (t === 'stop' || t === 'stop_limit') p.push(['orderType', 'stp']);
  else if (t === 'tp_market') p.push(['orderType', 'take_profit']);
  else if (t === 'limit') p.push(['orderType', 'lmt']);
  else if (t === 'market') p.push(['orderType', 'mkt']);
  else return null;
  p.push(['symbol', String(symbol)]);
  p.push(['side', String(side).toLowerCase() === 'buy' ? 'buy' : 'sell']);
  p.push(['size', String(qty)]);
  if ((t === 'limit' || t === 'stop_limit') && price != null) {
    p.push(['limitPrice', String(price)]);
  }
  if (t === 'stop' || t === 'stop_limit' || t === 'tp_market') {
    p.push(['stopPrice', String(f.trigger)]);
    p.push(['triggerSignal', 'mark']);
  }
  if (f.reduceOnly) p.push(['reduceOnly', 'true']);
  const cid = krClOrdId(clOrdID);
  if (cid) p.push(['cliOrdId', cid]);
  return p;
}
// Spot /0/private/AddOrder param list (pair = ALTNAME; volume = BASE qty).
function krSpotOrderParams(alt, side, ordType, qty, price, clOrdID) {
  const p = [['pair', String(alt)],
             ['type', String(side).toLowerCase() === 'buy' ? 'buy' : 'sell'],
             ['ordertype', String(ordType).toLowerCase() === 'limit' ? 'limit' : 'market'],
             ['volume', String(qty)]];
  if (String(ordType).toLowerCase() === 'limit') p.push(['price', String(price)]);
  const cid = krClOrdId(clOrdID);
  if (cid) p.push(['cl_ord_id', cid]);
  return p;
}
// --- Kraken private WebSockets (#1804 — nonce-free private path) ------------
// One key shared by the server engine and this signer runs TWO strictly-
// increasing REST nonce streams → permanent EAPI:Invalid nonce. The WS
// interface has no per-request nonces: spot rides WS-v2 (one
// GetWebSocketsToken REST call, then executions/balances streams + order
// entry on the socket); futures rides ws/v1 challenge-signed feeds. The
// pure converters below re-shape WS frames into the EXACT REST payload
// shapes execKrakenAcctRead already returns, so the panel parser stays the
// single source of truth (byte-compatible with the REST path).
const KRAKEN_SPOT_WS_URL = 'wss://ws-auth.kraken.com/v2';
const KRAKEN_FUT_WS_URL = 'wss://futures.kraken.com/ws/v1';
const KR_WS_ENABLE_HINT = 'enable the "WebSocket interface" permission on '
  + 'your kraken.com API key (Settings \u2192 API), then reconnect';
// Futures ws/v1 challenge signature: b64(HMAC-SHA512(b64decode(secret),
// SHA256(challenge))) — kr_fut_ws_sign golden parity.
function krFutWsSign(secretB64, challenge) {
  const digest = crypto.createHash('sha256')
    .update(String(challenge), 'utf8').digest();
  return crypto.createHmac('sha512', Buffer.from(String(secretB64), 'base64'))
    .update(digest).digest('base64');
}
// GetWebSocketsToken "Permission denied" → the key lacks the WebSocket
// interface toggle; actionable message (null for every other error).
function krWsPermMsg(err) {
  if (String(err || '').toLowerCase().indexOf('permission denied') >= 0) {
    return 'Kraken WS token refused \u2014 ' + KR_WS_ENABLE_HINT;
  }
  return null;
}
// Spot WS-v2 executions order_status values that mean the order LEFT the book.
const KR_WS_SPOT_GONE = { filled: 1, canceled: 1, cancelled: 1, expired: 1 };
// --- Kraken native fills cache (#1814) --------------------------------------
// The WS sessions ingest executions into a bounded per-scope cache so a
// device-key-only setup has a fills source (the server engine has no key).
// RAW venue rows are cached verbatim — the ENGINE parses them with its own
// normalizers via /native_fills (single parser truth, phemex precedent).
// Spot WS-v2 executions trade event → cache row. null = not a trade fill.
function krWsSpotFillRow(e) {
  if (!e || typeof e !== 'object') return null;
  if (String(e.exec_type || '') !== 'trade') return null;
  if (!String(e.exec_id || e.trade_id || '')) return null;
  if (!(Number(e.last_qty) > 0)) return null;
  const ts = e.timestamp ? Date.parse(e.timestamp) : NaN;
  return { id: String(e.exec_id || e.trade_id),
           ts: Number.isFinite(ts) ? ts : Date.now(), raw: e };
}
// #1878: bounded push copy of a spot WS execution trade row — exactly the
// fields the panel's fills-lane parser (krFillsStateRows) reads, so a pushed
// row and the later poll/read copy of the SAME fill produce identical merged
// rows (eid 's:<exec_id>') and dedupe to a no-op. Null for non-trade rows.
function krPushFillRow(e, ord) {
  if (!e || typeof e !== 'object') return null;
  if (String(e.exec_type || '') !== 'trade') return null;
  if (!String(e.exec_id || e.trade_id || '')) return null;
  // #1881: burst exec rows may omit `symbol` — backfill from the ledger's
  // order row (looked up BEFORE the fill consumes it) so the pushed seed
  // row never silently drops while its fid still rides the event (the old
  // asymmetry: sound counted the fill, the lot accumulator never saw it).
  const sym = e.symbol != null && e.symbol !== '' ? e.symbol
            : (ord && ord.symbol != null ? ord.symbol : '');
  if (!(Number(e.last_qty) > 0) || !sym) return null;
  const r = { exec_type: 'trade', symbol: String(sym),
              side: String(e.side || ''), last_qty: e.last_qty,
              last_price: e.last_price == null ? '0' : e.last_price };
  if (e.exec_id != null) r.exec_id = String(e.exec_id);
  if (e.trade_id != null) r.trade_id = String(e.trade_id);
  if (e.order_id != null) r.order_id = String(e.order_id);
  if (e.timestamp != null) r.timestamp = e.timestamp;
  // #1881 seed-math parity: fees ride the pushed row in the SAME shape the
  // REST TradesHistory seed rows carry (krRestSpotWsRow), so the panel's
  // fee-aware cost-basis replay computes the SAME avg from either copy.
  if (Array.isArray(e.fees) && e.fees.length) {
    r.fees = e.fees.slice(0, 4).map(function (f) {
      return { asset: String((f || {}).asset || ''),
               qty: String((f || {}).qty == null ? '0' : (f || {}).qty) };
    });
  }
  if (e.cost != null) r.cost = String(e.cost);
  return r;
}
// Futures ws/v1 `fills` feed row → cache row. fill_id keys the dedupe — the
// SAME id REST /derivatives/api/v3/fills publishes, so engine-side dedupe
// keys stay identical to engine-fetched copies.
function krWsFutFillRow(f) {
  if (!f || typeof f !== 'object') return null;
  if (!String(f.fill_id || '')) return null;
  if (!(Number(f.qty) > 0)) return null;
  return { id: String(f.fill_id), ts: Number(f.time) || 0, raw: f };
}
// #1905: bounded push copy of a futures ws/v1 fill row — exactly the fields
// the panel's fills-lane parser (krFillsStateRows fut branch) and the
// engine's normalizer (norm_kr_ws_fut_fill) read, so a pushed row, the WS
// cache's fills_read copy and a REST-seed copy of the SAME fill all key
// 'f:<fill_id>' and dedupe to a no-op everywhere. Null for unusable rows.
function krPushFutFillRow(f) {
  if (!f || typeof f !== 'object') return null;
  if (!String(f.fill_id || '')) return null;
  if (!(Number(f.qty) > 0) || !String(f.instrument || '')) return null;
  const r = { instrument: String(f.instrument),
              time: Number(f.time) || 0,
              price: f.price == null ? '0' : f.price,
              buy: f.buy === true || f.buy === 'true' || f.buy === 1,
              qty: f.qty,
              fill_id: String(f.fill_id),
              order_id: f.order_id == null ? '' : String(f.order_id),
              fill_type: String(f.fill_type || '') };
  if (f.fee_paid != null) r.fee_paid = f.fee_paid;
  if (f.fee_currency != null) r.fee_currency = String(f.fee_currency);
  return r;
}
// #1905 fills_read clock-skew allowance (see execKrakenFillsRead).
const KR_FILLS_TS_SKEW_MS = 300000;
// Bounded dedupe push; oldest rows (and their seen keys) roll off past cap.
// Cache cap must hold a FULL seed walk (15 pages × ≤100 rows/page) or the
// paged restart self-heal would evict its own oldest legs on push.
const KR_FILLS_CACHE_CAP = 1600;
function krFillsCachePush(C, row, cap) {
  if (!C || !row) return false;
  if (C.seen[row.id]) return false;
  cap = cap || KR_FILLS_CACHE_CAP;
  C.seen[row.id] = 1;
  C.rows.push(row);
  if (C.rows.length > cap) {
    const drop = C.rows.splice(0, C.rows.length - cap);
    for (const d of drop) delete C.seen[d.id];
  }
  lbSrcTouch(C);   // #2230 the ONE Kraken choke point (WS live + REST seed)
  return true;
}
// fills_read window filter: RAW rows with ts inside [startMs, endMs].
function krFillsWindow(C, startMs, endMs) {
  const out = [];
  for (const r of ((C && C.rows) || [])) {
    if (r.ts >= startMs && r.ts <= endMs) out.push(r.raw);
  }
  return out;
}
// fills_read per-scope gate: a scope is readable ONLY when its WS is live
// AND the seed snapshot (spot snap_trades / futures fills_snapshot) has
// landed. An empty read before seeding would let the panel advance its
// coverage cursor past the seed window — snapshot fills arriving later
// would then fall outside the 2-min overlap and never reach the archive.
function krFillsScopeReady(live, C) {
  return !!(live && C && C.seeded);
}
// #1835: private-WS lag instrumentation. Kraken's executions echo lands
// ~3-6s late in some sessions while REST RTT through the SAME proxy is
// ~370ms — quantify WHERE the seconds go (venue-side delivery vs shell-side
// handling). Per-connection recorder: raw lag = local arrival − venue event
// ts (includes clock offset), base = rolling MIN over the connection's life
// (clock-independent — the stream-lag rule: report delay ABOVE the best the
// stream ever showed, never trust raw clock deltas alone); applyUs = shell
// time from socket message to state applied (shell-side suspect gauge).
// Bounded: sample caps, snapshot drains + resets — the caller emits ONE
// diag event per minute per scope, never per event.
function krLagNew(conn) {
  return { conn: conn | 0, lags: [], applyUs: [], base: null };
}
function krLagRec(L, lagMs, applyUs) {
  if (!L || !Number.isFinite(lagMs)) return;
  if (L.base == null || lagMs < L.base) L.base = lagMs;
  if (L.lags.length < 600) L.lags.push(lagMs);
  if (Number.isFinite(applyUs) && applyUs >= 0 && L.applyUs.length < 600) {
    L.applyUs.push(applyUs);
  }
}
function krLagPct(sorted, p) {
  if (!sorted.length) return 0;
  const i = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[i];
}
function krLagSnap(L) {
  if (!L || !L.lags.length) return null;
  const s = L.lags.slice().sort((a, b) => a - b);
  const a = L.applyUs.slice().sort((x, y) => x - y);
  const out = { conn: L.conn, n: s.length,
                p50: Math.round(krLagPct(s, 50)), p95: Math.round(krLagPct(s, 95)),
                max: Math.round(s[s.length - 1]), base: Math.round(L.base),
                applyP95Us: a.length ? Math.round(krLagPct(a, 95)) : 0 };
  L.lags = []; L.applyUs = [];
  return out;
}
// #1820 one-shot REST own-trades seed converters: REST rows convert into the
// SAME raw WS shapes the caches hold, so the ENGINE's WS normalizers parse
// them and the exec-id dedupe collapses the REST/WS copies of one fill (spot
// WS-v2 exec_id IS the TradesHistory txid — same T…-…-… space; futures
// fill_id is REST-identical by design). Truth rule: an unmappable pair code
// returns null — never record a guessed symbol.
// Spot /0/private/TradesHistory result.trades entry → WS-v2 executions shape.
function krRestSpotWsRow(tid, t, codeMap) {
  if (!tid || !t || typeof t !== 'object') return null;
  const sym = (codeMap || {})[String(t.pair || '')];
  if (!sym) return null;
  const ms = Math.round(Number(t.time) * 1000);
  if (!(ms > 0) || !(Number(t.vol) > 0)) return null;
  const quote = String(sym).split('/')[1] || '';
  const row = { exec_type: 'trade', exec_id: String(tid),
                order_id: String(t.ordertxid || ''),
                symbol: sym, side: String(t.type || '').toLowerCase(),
                last_qty: String(t.vol), last_price: String(t.price || '0'),
                fees: (Number(t.fee) > 0 && quote)
                  ? [{ asset: quote, qty: String(t.fee) }] : [],
                timestamp: new Date(ms).toISOString() };
  if (t.cost != null) row.cost = String(t.cost);
  return row;
}
// Seed pagination (pure): spot TradesHistory is offset-paged (50/page,
// server-side start bound); returns the next `ofs` or null when the window
// is covered. Mirrors the engine's _spot_trades_walk termination rule.
function krSeedSpotNext(res, ofs, got) {
  if (!got || got < 50) return null;
  const total = Number((res || {}).count) || 0;
  const next = ofs + got;
  return next < total ? next : null;
}
// Futures /api/v3/fills pages BACKWARDS via lastFillTime (≤100 fills before
// it). Returns the next cursor ISO, or null once a short page arrives or the
// page already reaches past startMs. Mirrors the engine's _fut_fills_walk.
function krSeedFutNext(fills, startMs) {
  if (!Array.isArray(fills) || fills.length < 100) return null;
  let oldest = null;
  for (const f of fills) {
    const t = Date.parse(String(((f || {}).fillTime) || ''));
    if (Number.isFinite(t) && (oldest === null || t < oldest)) oldest = t;
  }
  if (oldest === null || oldest <= startMs) return null;
  return new Date(oldest).toISOString();
}
// Futures GET /derivatives/api/v3/fills row → ws/v1 fills feed shape.
function krRestFutWsRow(f) {
  if (!f || typeof f !== 'object' || !String(f.fill_id || '')) return null;
  const ms = Date.parse(String(f.fillTime || ''));
  if (!Number.isFinite(ms) || !(Number(f.size) > 0)) return null;
  return { instrument: String(f.symbol || '').toUpperCase(),
           time: ms, price: f.price,
           buy: String(f.side || '').toLowerCase() === 'buy',
           qty: f.size, order_id: String(f.order_id || ''),
           fill_id: String(f.fill_id),
           fill_type: String(f.fillType || '') };
}
// ws/v1 open_orders order dict → REST openorders row shape (qty=REMAINING;
// direction 1=sell; type limit/stop/take_profit → lmt/stop/take_profit).
function krWsFutOrderRest(o) {
  const t = String((o || {}).type || '').toLowerCase();
  return {
    order_id: String((o || {}).order_id || ''),
    symbol: String((o || {}).instrument || '').toUpperCase(),
    side: ((o || {}).direction === 1 || (o || {}).direction === '1') ? 'sell' : 'buy',
    orderType: t === 'limit' ? 'lmt' : t,
    limitPrice: (o || {}).limit_price,
    stopPrice: (o || {}).stop_price,
    unfilledSize: (o || {}).qty,
    filledSize: (o || {}).filled || 0,
    reduceOnly: !!(o || {}).reduce_only,
    cliOrdId: (o || {}).cli_ord_id,
    receivedTime: (o || {}).time,
  };
}
// ws/v1 open_positions row → REST openpositions row shape (signed balance).
function krWsFutPosRest(p) {
  const bal = Number((p || {}).balance);
  if (!Number.isFinite(bal) || bal === 0) return null;
  return {
    side: bal < 0 ? 'short' : 'long',
    symbol: String((p || {}).instrument || '').toUpperCase(),
    size: Math.abs(bal),
    price: (p || {}).entry_price,
    effectiveLeverage: (p || {}).effective_leverage,
    initialMargin: (p || {}).initial_margin,
  };
}
// ws/v1 balances flex_futures (snake_case) → REST /accounts payload shape.
function krWsFlexRest(flex) {
  const f = flex || {};
  const cur = {};
  const c = f.currencies || {};
  for (const k of Object.keys(c)) {
    const e = c[k] || {};
    cur[k] = { quantity: e.quantity, value: e.value,
               collateral: e.collateral_value, available: e.available };
  }
  return { accounts: { flex: {
    balanceValue: f.balance_value,
    portfolioValue: f.portfolio_value,
    initialMargin: f.initial_margin,
    availableMargin: f.available_margin,
    currencies: cur,
  } } };
}
// WS-v2 spot open orders (raw element map) → per-asset holds: a resting
// SELL holds remaining BASE, a resting limit BUY holds remaining×price QUOTE.
function krWsSpotHolds(orders) {
  const holds = {};
  for (const oid of Object.keys(orders || {})) {
    const e = orders[oid] || {};
    const sym = String(e.symbol || '');
    if (sym.indexOf('/') < 0) continue;
    const parts = sym.split('/');
    const rem = (Number(e.order_qty) || 0) - (Number(e.cum_qty) || 0);
    if (!(rem > 0)) continue;
    if (String(e.side || '').toLowerCase() === 'sell') {
      holds[parts[0]] = (holds[parts[0]] || 0) + rem;
    } else if (e.limit_price != null && Number(e.limit_price) > 0) {
      holds[parts[1]] = (holds[parts[1]] || 0) + rem * Number(e.limit_price);
    }
  }
  return holds;
}
// WS-v2 balances totals + derived holds → REST BalanceEx payload shape.
function krWsSpotBalanceEx(totals, holds) {
  const result = {};
  for (const a of Object.keys(totals || {})) {
    const bal = Number(totals[a]) || 0;
    let h = Number((holds || {})[a]) || 0;
    if (h < 0) h = 0;
    if (h > bal) h = bal;
    if (bal === 0 && h === 0) continue;
    result[a] = { balance: String(totals[a]), hold_trade: String(h) };
  }
  return { error: [], result: result };
}
// WS-v2 spot open orders → REST OpenOrders [{txid, o}] rows (descr.pair =
// ALTNAME via the symbol→alt map from the public catalog).
function krWsSpotOpenOrders(orders, altOf) {
  const rows = [];
  for (const oid of Object.keys(orders || {})) {
    const e = orders[oid] || {};
    const sym = String(e.symbol || '');
    rows.push({ txid: oid, o: {
      descr: {
        pair: (altOf && altOf[sym] && altOf[sym].alt) || sym.replace('/', ''),
        type: String(e.side || '').toLowerCase() === 'sell' ? 'sell' : 'buy',
        ordertype: String(e.order_type || 'limit').toLowerCase(),
        price: e.limit_price == null ? '0' : String(e.limit_price),
      },
      vol: e.order_qty == null ? '0' : String(e.order_qty),
      vol_exec: e.cum_qty == null ? '0' : String(e.cum_qty),
      status: 'open',
      cl_ord_id: e.cl_ord_id || undefined,
      opentm: e.timestamp ? Date.parse(e.timestamp) / 1000 : undefined,
    } });
  }
  return rows;
}

// --- #1822 optimistic REST/WS-ack echo (pure) -------------------------------
// Kraken's private WS delivers execution echoes ~3–6s late over proxied
// routes (measured: order ack t+0.4s, WS execution rows t+5.6s). Since #1804
// the acct reads are WS-first, so order badges + spot holds waited on the
// echo. On a successful order/cancel ACK the shell mutates its OWN WS
// session order maps immediately: place → synthetic row (marked _synTs,
// TTL-bounded — venue truth replaces it, expiry is fail-visible), cancel /
// cancel_all → rows dropped. Totals are NEVER fabricated (truth rule) —
// holds recompute from the corrected orders map, which is exactly the
// free/locked split that flapped the posrow after Space.
const KR_SYN_TTL_MS = 15000;
// Synthetic spot WS-v2 executions row (limit only — market orders never rest).
function krSynSpotOrder(oid, symbol, side, qty, price, cid, now) {
  const row = { order_id: String(oid), symbol: String(symbol),
                side: String(side).toLowerCase() === 'sell' ? 'sell' : 'buy',
                order_type: 'limit', order_qty: Number(qty), cum_qty: 0,
                limit_price: Number(price),
                timestamp: new Date(now).toISOString(), _synTs: now,
                _bornTs: now };   // #1874 audit-omission birth stamp
  if (cid) row.cl_ord_id = String(cid);
  return row;
}
// Synthetic futures ws/v1 open_orders row (qty is REMAINING on that feed).
function krSynFutOrder(oid, symbol, side, qty, price, cid, reduceOnly, now) {
  const row = { order_id: String(oid),
                instrument: String(symbol).toUpperCase(),
                direction: String(side).toLowerCase() === 'sell' ? 1 : 0,
                type: 'limit', limit_price: Number(price), qty: Number(qty),
                filled: 0, reduce_only: !!reduceOnly, time: now, _synTs: now,
                _bornTs: now };   // #1874 audit-omission birth stamp
  if (cid) row.cli_ord_id = String(cid);
  return row;
}
// Expire never-confirmed synthetic rows (fail-visible: after the TTL the
// badge honestly drops instead of fabricating a permanent order). In place.
// #1876: expiry additionally requires SNAPSHOT TESTIMONY — a post-birth
// venue snapshot must have omitted the row (_omitTs armed by
// krOrdersReconcile). The bare TTL wiped 5 real resting orders whose WS
// echo never came while every snapshot LISTED them (listed rows now get
// _synTs cleared in the reconcile, but a budget-deferred audit left rows
// unconfirmed → the TTL alone deleted venue-ACKed orders). A row no
// snapshot ever testified against keeps its badge; the reconcile's double
// omission remains the honest removal path.
function krSynPrune(orders, now) {
  // Removal is owned by krOrdersReconcile (birth grace + double omission):
  // a snapshot listing the row confirms it, and only a SECOND later-fetched
  // snapshot that also omits it may delete. A time-based prune here could
  // delete on a single armed omission — exactly the false badge wipe the
  // double-omission rule prevents — so this sweep deletes nothing. Kept as
  // a call-site-stable no-op (seq/diag behavior unchanged: it never fires).
  void orders; void now;
  return 0;
}
// Snapshot-race carry: the spot session goes live on the subscribe ACKs,
// BEFORE its executions snapshot is applied — an order ACKed in that gap
// writes a synthetic row the (older) snapshot cannot contain, so a plain
// `S.orders = {}` reset would erase it and resurrect the multi-second
// missing-badge/hold gap. Carry ONLY still-fresh synthetic rows across the
// reset; they stay TTL-bounded (krSynPrune) and echo-confirmed as usual.
function krSynCarry(orders, now) {
  const kept = {};
  for (const oid of Object.keys(orders || {})) {
    const ts = (orders[oid] || {})._synTs;
    if (ts != null && now - ts <= KR_SYN_TTL_MS) kept[oid] = orders[oid];
  }
  return kept;
}
// cancel_all ACK sweep: drop every row on the symbol. field = 'symbol'
// (spot WS-v2 rows) or 'instrument' (futures ws/v1 rows); case-insensitive.
function krSynSweepSymbol(orders, symbol, field) {
  const want = String(symbol || '').toUpperCase();
  const gone = [];
  if (!want) return gone;
  for (const oid of Object.keys(orders || {})) {
    if (String((orders[oid] || {})[field] || '').toUpperCase() === want) {
      delete orders[oid];
      gone.push(oid);
    }
  }
  return gone;
}

// --- #1826 Kraken post-trade fast lane (pure) -------------------------------
// #1822's optimistic echo fixed the badges, but a live diag log showed two
// gaps remained: (1) the acct_read result memo (acctReadGuard) can serve a
// PRE-ack snapshot for up to ACCT_READ_MEMO_MS after a trade ack — nothing
// invalidated it; (2) spot balances stay venue-truth (never fabricated), so
// the posrow still waited on Kraken's ~3–6s-late WS balance echo. Fix: bust
// the memoized VALUE on every successful kraken trade ack (single-flight
// state untouched) + ONE bounded venue-truth REST confirm (BalanceEx +
// OpenOrders) shortly after the ack, coalesced across ack bursts.
const KR_CONFIRM_DELAY_MS = 400;      // ack → confirm (venue settle window)
const KR_CONFIRM_MIN_GAP_MS = 1000;   // confirms never fire closer than this
const KR_CONFIRM_TRADES_WINDOW_MS = 10 * 60 * 1000;  // recent own-trades page
// Coalescing gate — pure state machine over an injected clock so the burst /
// min-gap / rerun-after-in-flight behavior is node-testable. State shape:
// { timerAt: null|ts, running: bool, again: bool, lastEnd: ts }.
// kick(): returns the ms to wait before firing, or null when a timer is
// already pending (burst coalesced) / a run is in flight (rerun latched).
function krConfirmKick(st, now) {
  if (st.timerAt != null) return null;               // burst → one timer
  if (st.running) { st.again = true; return null; }  // rerun after in-flight
  const at = Math.max(now + KR_CONFIRM_DELAY_MS,
                      (st.lastEnd || 0) + KR_CONFIRM_MIN_GAP_MS);
  st.timerAt = at;
  return at - now;
}
// fire(): timer elapsed — true = run the confirm now (never two in flight).
function krConfirmFire(st) {
  st.timerAt = null;
  if (st.running) { st.again = true; return false; }
  st.running = true;
  return true;
}
// done(): confirm finished — true = an ack landed mid-run, kick once more.
function krConfirmDone(st, now) {
  st.running = false;
  st.lastEnd = now;
  const again = st.again;
  st.again = false;
  return again;
}
// REST asset code → WS-v2 asset name (kr_asset_norm engine parity: 4-char
// X/Z prefix strip FIRST, then staking suffix drop, then XBT/XDG fixes).
function krAssetWsName(code) {
  let s = String(code || '');
  if (s.length === 4 && (s[0] === 'X' || s[0] === 'Z')) s = s.slice(1);
  s = s.split('.')[0];
  return ({ XBT: 'BTC', XDG: 'DOGE' })[s] || s;
}
// BalanceEx response → WS totals map. Duplicate codes SUM per normalized
// name (XXBT + XBT.F → one BTC row — engine balances() parity; the panel
// holding lookup takes the FIRST row, so a dust variant must never mask
// the real balance). Values stay strings (WS balances shape).
function krBalanceExTotals(data) {
  const res = ((data || {}).result) || {};
  const out = {};
  for (const code of Object.keys(res)) {
    const a = krAssetWsName(code);
    const b = Number(((res[code] || {}).balance));
    if (!a || !Number.isFinite(b)) continue;
    out[a] = (out[a] || 0) + b;
  }
  for (const a of Object.keys(out)) out[a] = String(out[a]);
  return out;
}
// Post-confirm reconcile (#1828): the venue-truth OpenOrders page is the
// FULL open set for the account — ANY map row absent from it is confirmed
// gone, synthetic AND WS-echoed alike (an order that fills instantly as
// taker produces no cancel and the WS "filled" echo can arrive tens of
// seconds late or drop entirely; the badge must not wait it out). Spot map
// keys ARE the REST txids (same id space — no mangling). Fresh rows get a
// grace window: OpenOrders itself lags just-ACKed adds (#1822 lesson), so a
// just-placed order must not have its badge eaten by the confirm it
// triggered — _synTs (optimistic add) or _updTs (last WS write) both count.
const KR_CONFIRM_ORDER_GRACE_MS = 2500;
// #1874 audit omission grace: a Kraken REST OpenOrders snapshot can itself
// lag and OMIT just-placed orders (observed: 4 live resting badges wiped by
// an audit whose fill-seq guard passed — the ledger hadn't moved, but the
// venue page was stale). Omission from a snapshot may only remove a row
// when the order is older than the birth grace AND missing from TWO
// consecutive snapshots FETCHED AFTER its birth; otherwise the omission is
// withheld (caller diag-logs kr_audit_omit) and the badge stays. WS-gone /
// cancel deletes never ride this path — they delete directly. Birth =
// _bornTs (stamped at first WS/synthetic insertion), falling back to
// _synTs/_updTs; rows with no stamp at all (pre-upgrade REST-seeded) are
// treated as old but still need the double omission. `fetchTs` = when the
// snapshot request STARTED (defaults to `now` for legacy callers).
// Returns { gone: [oid...], omit: [oid...] }.
const KR_AUDIT_BIRTH_GRACE_MS = 60000;
function krOrdersReconcile(orders, liveIds, now, fetchTs) {
  const live = {};
  for (const id of (liveIds || [])) live[String(id)] = 1;
  const ft = (fetchTs != null) ? +fetchTs : +now;
  const gone = [], omit = [];
  for (const oid of Object.keys(orders || {})) {
    const o = orders[oid] || {};
    if (live[oid]) {
      if (o._omitTs != null) delete o._omitTs;
      // #1876: a venue snapshot LISTING the row IS venue truth — confirm the
      // optimistic synthetic so the fail-visible TTL (krSynPrune) can't wipe
      // a live resting order the WS echo never confirmed (observed: 5 badges
      // gone ~15-20s after birth with a quiet WS but green audits).
      if (o._synTs != null) { delete o._synTs; o._updTs = +now; }
      continue;
    }
    // #1881: omission grace NEVER protects a fully-filled row — own fills
    // already consumed it, the snapshot omitting it is right. Immediate
    // removal (no birth grace, no double omission) makes ghost re-adds
    // impossible regardless of tombstone TTL.
    if (krOrderFilled(o)) { delete orders[oid]; gone.push(oid); continue; }
    const ts = (o._synTs != null) ? o._synTs
             : (o._updTs != null) ? o._updTs : null;
    if (ts != null && now - ts <= KR_CONFIRM_ORDER_GRACE_MS) continue;
    const born = (o._bornTs != null) ? +o._bornTs : (ts != null ? +ts : 0);
    // young order, or the snapshot was fetched before the order existed —
    // the page cannot testify about it; withhold (never resets omit state)
    if (born > 0 && (now - born < KR_AUDIT_BIRTH_GRACE_MS || ft <= born)) {
      omit.push(oid); continue;
    }
    // first qualifying omission → arm; a SECOND snapshot (fetched strictly
    // later than the armed one) must also omit it before the row drops
    if (!(o._omitTs > 0)) { o._omitTs = ft; omit.push(oid); continue; }
    if (ft <= o._omitTs) { omit.push(oid); continue; }
    delete orders[oid]; gone.push(oid);
  }
  return { gone: gone, omit: omit };
}

// --- #1860 local-first ledger (pure) ----------------------------------------
// The WS session maps (S.orders / S.totals) ARE the authoritative local
// ledger: own actions mutate them synchronously (#1822 synthetics, cancel
// deletes), the private WS confirms/corrects them, and REST snapshots are a
// background AUDITOR. Two pure pieces pin the contract:
//   krLseq   — monotonic mutation seq per scope (spot/fut), bumped by every
//              ledger write; stamped on acct reads + diag so logs show
//              display truth directly.
//   krLedgerFreshIds — when a read falls back to REST (WS down), the venue
//              snapshot may predate just-ACKed orders; any ledger row that
//              is FRESH (optimistic within TTL, or WS-echoed within the
//              reconcile grace) and absent from the snapshot is overlaid on
//              top so a badge/hold never vanishes to a stale page. Stale
//              ledger rows are NOT overlaid — the auditor wins for those.
function krLseq(scope) { if (scope) scope.lseq = (scope.lseq | 0) + 1; }
// --- #1867 push channel (pure) --------------------------------------------
// The shell pushes every Kraken ledger mutation to the panel windows the
// moment it lands (badges/posrow/sound react to the push; the /state poll
// stays a background auditor). Mutations coalesce per scope key
// ('slot|scope') inside one flush window — a cancel_all burst becomes ONE
// event per scope with the kinds union and the LATEST lseq (seq is read at
// drain time, so a window comparing seqs can detect it already applied it).
const KR_PUSH_COALESCE_MS = 25;
// #1870: 'fill' marks may carry the individual fill id — the drained event
// ships the ids so the panel chime plays PER FILL at push time instead of
// waiting out the fills-read cycle. Bounded + deduped (a pathological frame
// can't balloon the IPC payload; the panel latches ids anyway).
const KR_PUSH_FIDS_CAP = 24;
// #1874: 'ordgone' marks a REMOVED order row (fill-consumed / cancel-
// confirmed / WS-gone / audit-confirmed). The drained event ships the gone
// oids (ev.goids) so every panel window tombstones + drops the badge in the
// SAME push apply pass — never waiting out an acct read that may be busy or
// racing a stale in-flight snapshot (observed 1.5-5.7s badge-del lag).
// 'ordgone' folds into the 'order' kind on the wire (consumers key on it).
function krPushMark(P, key, kind, id, row) {
  if (!P[key]) P[key] = { kinds: {} };
  const k = String(kind || 'ledger');
  P[key].kinds[k === 'ordgone' ? 'order' : k] = 1;
  if (id != null && k === 'fill') {
    if (!P[key].fids) P[key].fids = [];
    const s = String(id);
    if (P[key].fids.length < KR_PUSH_FIDS_CAP && P[key].fids.indexOf(s) < 0) {
      P[key].fids.push(s);
    }
    // #1878: the pushed fill's price/qty row rides the event — the panel
    // seeds the posrow cost-basis replay from it the SAME push beat instead
    // of waiting out the rate-budget-deferred fills read (observed 4-6s "—"
    // on close→instant-reopen). Bounded like fids; rows dedupe panel-side
    // by exec id (same 's:<exec_id>' namespace as the poll lane).
    if (row && typeof row === 'object') {
      if (!P[key].frows) P[key].frows = [];
      if (P[key].frows.length < KR_PUSH_FIDS_CAP) P[key].frows.push(row);
    }
  }
  // #1894: pushed order ADD/UPDATE row (REST shape) rides the event — the
  // panel merges it into its applied acct state at push time so the SL/TP
  // badge renders that beat instead of waiting out a busy/paced acct read
  // (observed 0.7-2.5s badge-add lag, worst on the 2nd of an SL+TP pair).
  // Bounded like fids; panel replaces-by-oid so re-pushes dedupe there.
  if (row && typeof row === 'object' && k === 'order') {
    if (!P[key].orows) P[key].orows = [];
    if (P[key].orows.length < KR_PUSH_FIDS_CAP) P[key].orows.push(row);
  }
  // #1945: pushed POSITION rows (Binance futures ACCOUNT_UPDATE a.P) and
  // BALANCE rows (a.B futures / outboundAccountPosition B spot) ride the
  // event — the panel steps posrow qty/entry/uPnL and wallets on the push
  // beat instead of waiting out the paced 1-1.5s REST re-read (observed
  // bn_apply maxMs 1219-1545 vs Kraken's ~1ms). Kind-only marks (no row)
  // stay byte-identical for Kraken and old panel builds (additive lanes).
  if (row && typeof row === 'object' && k === 'pos') {
    if (!P[key].prows) P[key].prows = [];
    if (P[key].prows.length < KR_PUSH_FIDS_CAP) P[key].prows.push(row);
  }
  if (row && typeof row === 'object' && k === 'bal') {
    if (!P[key].brows) P[key].brows = [];
    if (P[key].brows.length < KR_PUSH_FIDS_CAP) P[key].brows.push(row);
  }
  if (id != null && k === 'ordgone') {
    if (!P[key].goids) P[key].goids = [];
    const g = String(id);
    if (P[key].goids.length < KR_PUSH_FIDS_CAP && P[key].goids.indexOf(g) < 0) {
      P[key].goids.push(g);
    }
  }
}
function krPushDrain(P, seqOf, nowMs, venue) {
  const out = [];
  for (const key of Object.keys(P)) {
    const ix = key.indexOf('|');
    const ev = { venue: venue || 'kraken', slot: key.slice(0, ix), scope: key.slice(ix + 1),
                 kinds: Object.keys(P[key].kinds).sort(),
                 seq: seqOf ? (seqOf(key) | 0) : 0, ts: nowMs };
    if (P[key].fids && P[key].fids.length) ev.fids = P[key].fids.slice();
    if (P[key].frows && P[key].frows.length) ev.frows = P[key].frows.slice();   // #1878 posrow seed rows
    if (P[key].goids && P[key].goids.length) ev.goids = P[key].goids.slice();
    if (P[key].orows && P[key].orows.length) ev.orows = P[key].orows.slice();   // #1894 order add/update rows
    if (P[key].prows && P[key].prows.length) ev.prows = P[key].prows.slice();   // #1945 position rows
    if (P[key].brows && P[key].brows.length) ev.brows = P[key].brows.slice();   // #1945 balance rows
    out.push(ev);
    delete P[key];
  }
  return out;
}
// Futures open_positions frames can re-deliver PnL-only refreshes — the push
// (and the lseq bump) must fire only when the PORTFOLIO changed (instrument /
// size / entry), never on a mark-price repaint, or scalp sessions would push
// continuously. Signature over identity fields only, order-insensitive.
function krFutPosSig(positions) {
  const rows = [];
  for (const p of (positions || [])) {
    if (!p || typeof p !== 'object') continue;
    rows.push(String(p.instrument || '') + '|' + String(p.balance != null ? p.balance : '') +
              '|' + String(p.entry_price != null ? p.entry_price : ''));
  }
  rows.sort();
  return rows.join(';');
}
function krLedgerFreshIds(orders, presentIds, now) {
  const present = {};
  for (const id of (presentIds || [])) present[String(id)] = 1;
  const out = [];
  for (const oid of Object.keys(orders || {})) {
    if (present[oid]) continue;
    const o = orders[oid] || {};
    const fresh =
      (o._synTs != null && now - o._synTs <= KR_SYN_TTL_MS) ||
      (o._updTs != null && now - o._updTs <= KR_CONFIRM_ORDER_GRACE_MS);
    if (fresh) out.push(oid);
  }
  return out;
}
// --- #1870 fill-consumption badge removal (pure) ---------------------------
// A trade execution that fully consumes its order must delete the ledger row
// in the SAME frame — the badge del rides the fill push beat (~10ms class,
// like cancel deletes), never a later "order gone" confirmation (observed
// 1.7-3.4s on red-zone taker fills). Full consumption = gone-family
// order_status, OR cum_qty >= order_qty (venue-reported, both > 0; the row's
// stored fields back-fill when the exec row omits them). Partial fills merge
// the exec fields onto the row (badge qty update) and stamp _updTs — a
// partial fill NEVER removes the badge. Returns 'gone' | 'upd' | null.
function krFillOrderApply(orders, e, now) {
  if (!orders || !e || typeof e !== 'object') return null;
  if (String(e.exec_type || '') !== 'trade') return null;
  const oid = String(e.order_id || '');
  if (!oid) return null;
  const row = orders[oid];
  const st = String(e.order_status || '').toLowerCase();
  const oq = Number(e.order_qty != null ? e.order_qty
                                        : (row && row.order_qty));
  let cq = Number(e.cum_qty);
  if (!(cq > 0)) {
    const pc = Number(row && row.cum_qty);
    const lq = Number(e.last_qty);
    cq = ((pc > 0) ? pc : 0) + ((lq > 0) ? lq : 0);
  }
  const consumed = (oq > 0 && cq >= oq * (1 - 1e-9));
  if (KR_WS_SPOT_GONE[st] || consumed) {
    delete orders[oid];
    return 'gone';
  }
  if (st === '' && !row) return null;   // snapshot/loose trade row — never a phantom badge
  orders[oid] = Object.assign({}, row || {}, e);
  // #1881: persist the ACCUMULATED cum_qty — burst execs often omit cum_qty,
  // and without storing the running sum every fill recomputed from the same
  // stale row value, so consumption never triggered and the ledger kept a
  // fully-consumed order open (kr_audit_omit then protected the ghost and
  // later order pushes re-added its badge 28-30s past the tombstone TTL).
  if (cq > 0) orders[oid].cum_qty = cq;
  if (!(Number(orders[oid].order_qty) > 0) && oq > 0) orders[oid].order_qty = oq;
  delete orders[oid]._synTs;   // venue echo confirms the optimistic row
  orders[oid]._updTs = now;
  return 'upd';
}
// #1881: a ledger row whose cumulative fills consumed its full qty is DEAD —
// own WS executions are authoritative, so no snapshot-omission grace, birth
// grace or freshness window may protect it (that protection is what kept
// burst-consumed orders alive: correct snapshots omitting them were
// distrusted, and later 'order' pushes re-added their badges past the
// tombstone TTL). Spot rows carry cum_qty/order_qty; futures ledger rows
// carry qty = REMAINING + filled = cumulative.
function krOrderFilled(o) {
  if (!o || typeof o !== 'object') return false;
  const oq = Number(o.order_qty);
  const cq = Number(o.cum_qty);
  if (oq > 0 && cq > 0 && cq >= oq * (1 - 1e-9)) return true;
  const rq = Number(o.qty);
  const fl = Number(o.filled);
  return fl > 0 && Number.isFinite(rq) && rq <= 0;
}
// Futures twin: ws/v1 `fills` rows carry remaining_order_qty — remaining→0
// deletes the row NOW (the open_orders echo that used to drive the delete
// lags the fill by seconds); remaining>0 updates the row's unfilled qty.
// Unknown order / no remaining info → null (never fabricate a row).
function krFutFillOrderApply(orders, f, now) {
  if (!orders || !f || typeof f !== 'object') return null;
  const oid = String(f.order_id || '');
  if (!oid || !orders[oid]) return null;
  const rq = Number(f.remaining_order_qty);
  if (!Number.isFinite(rq)) return null;
  if (rq <= 0) { delete orders[oid]; return 'gone'; }
  const row = orders[oid];
  row.qty = rq;
  const fq = Number(f.qty);
  if (fq > 0) row.filled = ((Number(row.filled) > 0) ? Number(row.filled) : 0) + fq;
  delete row._synTs;
  row._updTs = now;
  return 'upd';
}
// --- #1884 fill-before-order-registration race (pure) -----------------------
// A market order's consuming fill can land in the SAME WS beat the order is
// born — the fill-close runs before the ledger row exists, finds nothing to
// close, and the (later-processed) registration leaves the order OPEN
// forever (observed: NO kr_ord_gone; a routine /state render re-added the
// badge 29s later, right past the panel tombstone TTL — ~35s ghost).
// Two-part fix: (1) deterministic intra-frame apply order — registrations
// before trade rows (krExecsOrderFirst); (2) a short-lived CONSUMED-set of
// order ids own trade executions touched while their row was absent — a
// registration (WS delta OR snapshot) arriving for a consumed id closes
// immediately instead of opening (krConsumedTake), TTL-independent.
// Pending exec rows are retained (bounded) so the late registration can
// still ship the symbol-backfilled fill row to the panel's lot accumulator.
const KR_CONSUMED_TTL_MS = 30000;
const KR_CONSUMED_EXEC_MAX = 8;
// Deterministic intra-frame ordering: order registrations first, trade
// executions second — a fill riding the same frame always finds its row.
function krExecsOrderFirst(list) {
  const l = Array.isArray(list) ? list : [];
  const ords = [], fills = [];
  for (const e of l) {
    (String((e || {}).exec_type || '') === 'trade' ? fills : ords).push(e);
  }
  return (ords.length && fills.length) ? ords.concat(fills) : l;
}
function krConsumedPrune(map, now) {
  for (const k of Object.keys(map || {})) {
    if (!(now - map[k].ts <= KR_CONSUMED_TTL_MS)) delete map[k];
  }
}
// Note an own trade execution whose order row was ABSENT at apply time.
// note: { lastQty?, cumQty?, orderQty?, remaining?, gone?, exec? }
function krConsumedNote(map, oid, note, now) {
  if (!map || !oid || !note) return;
  krConsumedPrune(map, now);
  const r = map[oid] ||
    (map[oid] = { ts: now, cq: 0, rq: NaN, oq: 0, gone: false, execs: [] });
  r.ts = now;
  const lq = Number(note.lastQty);
  if (lq > 0) r.cq += lq;
  const cq = Number(note.cumQty);
  if (cq > 0 && cq > r.cq) r.cq = cq;
  const oq = Number(note.orderQty);
  if (oq > 0) r.oq = oq;
  const rq = Number(note.remaining);
  if (Number.isFinite(rq)) r.rq = rq;
  if (note.gone) r.gone = true;
  if (note.exec && r.execs.length < KR_CONSUMED_EXEC_MAX) r.execs.push(note.exec);
}
// A registration arrived for a possibly-consumed id. `row` is the incoming
// registration row (order_qty source). Returns null (nothing pending) or
// { eff: 'gone'|'upd', cq, rq, execs } — 'gone' = the fills already consumed
// the full qty (or reported a gone status / remaining 0): close NOW, never
// open. 'upd' = partial: caller merges the accumulated cum_qty onto the row.
function krConsumedTake(map, oid, row, now) {
  if (!map || !oid || !map[oid]) return null;
  const r = map[oid];
  delete map[oid];
  if (!(now - r.ts <= KR_CONSUMED_TTL_MS)) return null;
  const roq = Number(row && row.order_qty);
  const oq = (roq > 0) ? roq : r.oq;
  const gone = r.gone || (Number.isFinite(r.rq) && r.rq <= 0) ||
               (oq > 0 && r.cq >= oq * (1 - 1e-9));
  return { eff: gone ? 'gone' : 'upd', cq: r.cq, rq: r.rq, execs: r.execs };
}
// --- #1887 permanent per-session closed-order set (pure) --------------------
// TTL tombstones (#1876/#1878) stop SHORT-lag resurrections, but an
// instant-fill in-spread limit can have its GONE processed before its
// registration, and the late registration then reopens the id — a routine
// /state render re-adds the badge right past the panel tombstone TTL
// (observed: badge re-added ~29s after deletion, living another 29s).
// The closed set is PERMANENT for the scope's session: once an id pushed
// 'ordgone' (WS-gone, cancel ACK, fill-consumed, audit-confirmed — every
// gone rides the krPushSc choke point) NO later registration, snapshot,
// synthetic ack echo or /state-served map may reopen it. Bounded FIFO —
// a scalp session cannot grow it unbounded.
const KR_CLOSED_MAX = 5000;
function krClosedAdd(c, oid) {
  if (!oid) return c;
  const cc = c || { m: {}, q: [] };
  if (cc.m[oid]) return cc;
  cc.m[oid] = 1; cc.q.push(oid);
  while (cc.q.length > KR_CLOSED_MAX) delete cc.m[cc.q.shift()];
  return cc;
}
function krClosedHas(c, oid) { return !!(c && oid && c.m && c.m[oid]); }
// --- #1890 exactly-once fill ingest (pure) ----------------------------------
// The posrow qty accumulator double-counted a lot-opening fill when the
// balances DELTA for the trade beat its executions echo: the absolute
// balance already included the fill, then krFillTotalsApply added the same
// delta again (observed: posrow = exactly 2× the opening buy; sell-all
// rejected EOrder:Insufficient funds three times). Every totals ingest path
// (live exec row, learn-drain) now consults ONE shared gate before applying:
// (a) a bounded applied-id set keyed on the trade id — the spot exec_id IS
//     the ledger ref_id Kraken's balances rows carry, so a delta-first echo
//     notes the id and the exec row skips exactly; duplicate WS deliveries
//     of the same exec row skip too;
// (b) a venue-timestamp cover check — an APPLIED balances row for the BASE
//     asset stamped at/after the fill's venue ts proves the absolute
//     balance already includes the fill (works even when ref ids don't
//     match). Skipping is safe: the balance is venue truth.
function krFillIngestGate(applied, balTs, sym, fid, fts) {
  if (fid && krClosedHas(applied, fid)) return false;
  const base = String(sym || '').split('/')[0];
  if (base && balTs && balTs[base] != null && fts && balTs[base] >= fts) return false;
  return true;
}
// Balances update row → its ledger trade refs + newest venue ts. Kraken
// ships per-row ledger metadata either flat (ledger_id/ref_id/type/
// timestamp) or nested under `ledger`; a type:"trade" entry's ref_id is the
// SAME txid the executions channel ships as exec_id — exact echo dedupe.
// Rows without any ledger metadata return empty (guards stay inert).
function krBalRowRefs(r) {
  const out = { refs: [], ts: 0 };
  if (!r || typeof r !== 'object') return out;
  const rows = [];
  if (Array.isArray(r.ledger)) { for (const L of r.ledger) rows.push(L); }
  rows.push(r);
  for (const L of rows) {
    if (!L || typeof L !== 'object') continue;
    if (L.ledger_id == null && L.ref_id == null && L.type == null) continue;
    const ts = L.timestamp ? Date.parse(L.timestamp) : NaN;
    if (Number.isFinite(ts) && ts > out.ts) out.ts = ts;
    if (String(L.type || '').toLowerCase() !== 'trade') continue;
    const ref = String(L.ref_id || L.ledger_id || '');
    if (ref && out.refs.indexOf(ref) < 0) out.refs.push(ref);
  }
  return out;
}
// --- #1887 oid→symbol memory (pure) -----------------------------------------
// Spot WS-v2 trade exec rows may omit `symbol`; the old backfill read the
// ledger's order row — absent for an instant-fill limit whose registration
// lags the fill. Symbol-less fills then starve EVERYTHING downstream: the
// totals math no-ops (posrow qty rides lagging balance echoes → false-flat
// window), the pushed seed row drops (krPushFillRow null), and the poll
// copy is unparseable (fills-lane rows require symbol) — the lot
// accumulator never ingests a single fill (observed: 45 fills, zero avg
// renders). This map remembers oid→symbol from EVERY authoritative source
// (own order ACKs — we placed it, the symbol is the intent's —, WS
// registrations, symbol-carrying exec rows) so a fill can be backfilled
// regardless of registration state; bounded FIFO.
const KR_OIDSYM_MAX = 4000;
function krOidSymNote(map, oid, sym) {
  if (!oid || !sym) return map;
  const m = map || { m: {}, q: [] };
  if (m.m[oid] == null) {
    m.q.push(oid);
    while (m.q.length > KR_OIDSYM_MAX) delete m.m[m.q.shift()];
  }
  m.m[oid] = String(sym);
  return m;
}
function krOidSymGet(map, oid) {
  return (map && oid && map.m && map.m[oid] != null) ? map.m[oid] : null;
}
// Retro-fix cached raw exec rows that were stored symbol-less before the
// oid→symbol mapping was learned (fill beat the ACK/registration). Stamps
// `symbol` in place (the fills_read path serves these same raw objects, so
// the poll copy heals too) and returns the fixed rows so the caller can
// catch up the totals math + re-push symbol-complete seed rows. Bounded
// newest-first scan — symbol-less rows are always recent by construction.
const KR_SYMFIX_SCAN_MAX = 400;
function krFillsSymBackfill(rows, oid, sym, scanMax) {
  const out = [];
  if (!rows || !oid || !sym) return out;
  const cap = (scanMax == null) ? KR_SYMFIX_SCAN_MAX : scanMax;
  const n = rows.length;
  for (let i = n - 1, seen = 0; i >= 0 && seen < cap; i--, seen++) {
    const raw = (rows[i] || {}).raw;
    if (!raw || typeof raw !== 'object') continue;
    if (String(raw.order_id || '') !== String(oid)) continue;
    if (raw.symbol != null && raw.symbol !== '') continue;
    raw.symbol = String(sym);
    out.push(raw);
  }
  return out;
}
// --- #1870 stale-snapshot auditor gate (pure) -------------------------------
// A REST auditor snapshot may only mutate the ledger when (a) the response
// actually carries its data section — a budget-deferred / failed / body-error
// read must NEVER synthesize an empty set (observed: 5 live resting orders
// wiped by a snapshot fetched under rate-points pressure) — and (b) the WS
// ledger seq has NOT moved since the fetch started (the snapshot provably
// predates a mutation → discard, diag kr_audit_stale; the next confirm
// re-audits). Returns 'apply' | 'stale' | 'nodata'.
function krAuditGate(seq0, seqNow, hasData) {
  if (!hasData) return 'nodata';
  if ((seq0 | 0) !== (seqNow | 0)) return 'stale';
  return 'apply';
}

// --- #1876 gone-order tombstones (pure) -------------------------------------
// A fill-consumed / cancelled / WS-gone order deletes its ledger row in the
// push beat — but a LAGGING source (late WS delta echo, stale REST OpenOrders
// page, reconnect snapshot) that still lists the order as open used to
// RE-ADD the row (observed: badge del → re-add 10-11s later, stuck until the
// next cancel gesture). Every 'ordgone' removal now writes a tombstone in
// the scope (sc.tombs[oid] = removal ts); every re-add path consults it and
// drops the resurrection. TTL-bounded (same class as the panel's 12s cancel
// tombstones), and a snapshot FETCHED AFTER the removal that omits the id
// confirms it gone → the tombstone clears early (krTombConfirm).
const KR_TOMB_TTL_MS = 12000;
// #1878: SNAPSHOT-sourced adds get a LONGER shield. Audits/snapshots land
// 10-20s late under rate budget (kr_budget deferral + WS frame queueing), so
// the 12s TTL let a stale OpenOrders page re-add orders removed 10.9-11.3s
// earlier once the apply slipped past the TTL (observed v1.5.63: ghost
// badges 10-30s until the next cancel_all). Removal wins for the snap TTL —
// only a page still asserting the order PAST it re-shows honestly. Live
// delta echoes keep the tight 12s window.
const KR_TOMB_SNAP_TTL_MS = 30000;
function krTombAdd(tombs, oid, now) {
  const t = (tombs && typeof tombs === 'object') ? tombs : {};
  if (oid != null && oid !== '') t[String(oid)] = +now;
  return t;
}
function krTombHit(tombs, oid, now, ttl) {
  const ts = tombs && tombs[String(oid)];
  return ts != null && (+now - ts) <= (ttl == null ? KR_TOMB_TTL_MS : +ttl);
}
function krTombSweep(tombs, now) {
  // sweep at the LONGEST gate (snap TTL) — snapshot-add checks must still
  // see a tombstone the 12s delta window already released
  const t = (tombs && typeof tombs === 'object') ? tombs : {};
  for (const k of Object.keys(t)) {
    if (+now - t[k] > KR_TOMB_SNAP_TTL_MS) delete t[k];
  }
  return t;
}
// Snapshot fetched at fetchTs that OMITS a tombstoned id and postdates its
// removal = venue confirms the order gone → the tombstone has done its job.
function krTombConfirm(tombs, liveIds, fetchTs) {
  if (!tombs || typeof tombs !== 'object') return tombs;
  const live = {};
  for (const id of (liveIds || [])) live[String(id)] = 1;
  for (const k of Object.keys(tombs)) {
    if (!live[k] && +fetchTs > tombs[k]) delete tombs[k];
  }
  return tombs;
}

// --- #1832 Kraken spot private-REST points ledger (pure) --------------------
// Live diag proof (v1.5.44, 4.3min REPPO scalp): the #1826/#1828 fast lane
// (TradesHistory 2 + OpenOrders 1 + BalanceEx 1 per ack burst) exhausted
// Kraken's small private query counter (~15pts starter, decay ~0.33pt/s) and
// Kraken then rejected WHATEVER came next — including CancelOrder (cancel_all
// failed 2/6; a pressed Space left live orders). Kraken returns
// `EAPI:Rate limit exceeded` INSIDE an HTTP 200 body, so `s:200` diag rows
// looked healthy. Fix: a per-key token bucket mirroring the venue counter.
// STRICT priority — order/cancel calls never wait behind queries (they spend
// unconditionally); queries may spend only down to a reserved floor that
// keeps enough points for a burst of cancels, else they defer briefly or
// skip (fail-soft — the WS echo remains venue truth; a skipped confirm is
// logged via kr_budget, never an error). Sits ABOVE the signer/nonce path:
// gating happens before a nonce is drawn, so nonce serialization is intact.
const KR_LEDGER_MAX = 15;          // starter-tier private query counter
const KR_LEDGER_DECAY = 0.33;      // pts/s decay (starter — worst case)
const KR_LEDGER_FLOOR = 6;         // reserved: a burst of priority calls
const KR_QUERY_WAIT_MAX_MS = 2500; // queries defer at most this, then skip
const KR_CANCEL_RETRY_MS = 5000;   // bounded rate-limited cancel retry
const KR_CANCEL_RETRY_GAP_MS = 700;
// Private path → { cls, cost } (Kraken docs: TradesHistory/Ledgers-family
// cost 2, other queries 1; order entry/cancel ride a separate order limiter
// but a saturated query counter still rejects them, so they spend 1 as
// priority calls — recorded, never gated).
function krCallCost(path) {
  const p = String(path || '');
  if (/CancelOrder|CancelAll|CancelOrderBatch/i.test(p)) return { cls: 'cancel', cost: 1 };
  if (/AddOrder|EditOrder|AmendOrder/i.test(p)) return { cls: 'order', cost: 1 };
  if (/TradesHistory|Ledgers|QueryLedgers|QueryTrades|ClosedOrders|QueryOrders/i.test(p)) {
    return { cls: 'query', cost: 2 };
  }
  return { cls: 'query', cost: 1 };   // OpenOrders/BalanceEx/GetWebSocketsToken…
}
function krLedgerNew(now) { return { pts: KR_LEDGER_MAX, ts: Number(now) || 0 }; }
function krLedgerRefill(L, now) {
  const dt = Math.max(0, (Number(now) || 0) - L.ts) / 1000;
  L.pts = Math.min(KR_LEDGER_MAX, L.pts + dt * KR_LEDGER_DECAY);
  L.ts = Number(now) || 0;
}
// Gate a call: priority classes ('order'/'cancel') ALWAYS send (spend,
// clamped at 0 — the venue counter can't go negative on our mirror);
// queries send only while (pts - cost) stays >= the floor, else
// { waitMs } (bounded defer) or { skip:true } when the wait exceeds the cap.
function krLedgerGate(L, cls, cost, now) {
  krLedgerRefill(L, now);
  if (cls !== 'query') { L.pts = Math.max(0, L.pts - cost); return { send: true }; }
  if (L.pts - cost >= KR_LEDGER_FLOOR) { L.pts -= cost; return { send: true }; }
  const need = (KR_LEDGER_FLOOR + cost) - L.pts;
  const waitMs = Math.ceil((need / KR_LEDGER_DECAY) * 1000);
  if (waitMs > KR_QUERY_WAIT_MAX_MS) return { skip: true, waitMs: waitMs };
  return { waitMs: waitMs };
}
// Venue said `EAPI:Rate limit` → our mirror was optimistic; drain to 0 so
// queries back off for a full floor-refill while priority calls still send.
function krLedgerDrain(L, now) { L.pts = 0; L.ts = Number(now) || 0; }
// Non-mutating headroom peek (fast-lane trim decisions).
function krLedgerPts(L, now) {
  const dt = Math.max(0, (Number(now) || 0) - L.ts) / 1000;
  return Math.min(KR_LEDGER_MAX, L.pts + dt * KR_LEDGER_DECAY);
}
function krIsRateLimited(msg) { return /rate ?limit/i.test(String(msg || '')); }

// --- #2168 re-import reservation on the rate-points ledger (pure) -----------
// Field evidence (v1.5.97): the re-import walk's polite defer-and-retry
// ladder (lbKrBackfillRetry) lost EVERY ledger claim to steady-state account
// polling (now hot-first per #2131) — 6 deferrals / 374s, then an honest
// fail. An explicit user gesture must out-rank background polling for the
// SAME key's points WITHOUT exceeding the venue budget: while a walk holds a
// reservation on a spot key, routine (non-hot, non-priority) QUERY calls for
// that key skip immediately (no points spent — poll data goes stale-tolerant
// for a few cycles; WS push keeps live state per the local-ledger design),
// letting the ledger refill for the walk. Orders/cancels are untouched
// (priority classes never gate). Counted (nested acquire is fine) +
// TTL-guarded (a leaked reservation fails SAFE — polls resume; the walk is
// page-cap bounded far below the TTL). Reservations live in the Electron
// MAIN process — the same funnel as acctReadGuard — so all windows share one
// reservation and never fight.
const KR_RESV_TTL_MS = 10 * 60 * 1000;
function krResvNew() { return {}; }
function krResvAcquire(R, key, now) {
  const e = R[key] || (R[key] = { n: 0, ts: 0 });
  e.n++; e.ts = Number(now) || 0;
  return e.n;
}
function krResvRelease(R, key) {
  const e = R[key];
  if (!e) return 0;
  e.n--;
  if (e.n <= 0) { delete R[key]; return 0; }
  return e.n;
}
function krResvHeld(R, key, now) {
  const e = R[key];
  return !!(e && e.n > 0 && (Number(now) || 0) - e.ts < KR_RESV_TTL_MS);
}

// --- #1839 Kraken spot TRADING rate counter (pure) --------------------------
// SECOND, independent limiter (live diag proof, v1.5.47 REPPO scalp): the
// #1832 query ledger held (68 kr_budget events, zero query failures) yet 2
// cancel_alls STILL failed "rate limit persisted ~5s". Kraken spot has a
// separate TRADING counter with AGE PENALTIES on cancels: cancelling an
// order only seconds old costs up to +8 points (schedule below), decay is
// tier-dependent (~1/s starter … ~3.75/s pro). 15 sweeps × per-order
// CancelOrder on young orders exhausted it regardless of query points —
// hence the ONE-call bulk sweep + this mirror. Semantics: cancels are NEVER
// blocked (they spend, clamped at 0 — priority, exactly like the query
// ledger); order ADDS are softly gated (bounded pace wait, then send anyway
// flagged `paced`) so a Space sweep always has penalty headroom.
const KR_TRADE_MAX = 60;            // starter-tier trading counter
// #1864 re-audit: the TRADING counter decays 1 pt/s at starter tier (Kraken
// docs — the 0.33 figure belongs to the QUERY counter only; live sessions
// showed the 0.33 mirror draining ~3× faster than the venue and pacing adds
// to ~1.9s while Kraken itself never rejected). Amend rides the same counter
// at cost 1 with NO cancel age penalty — the replace gesture no longer pays
// the +8 young-cancel toll, which is where burst headroom went.
const KR_TRADE_DECAY = 1.0;         // pts/s decay (starter trading counter)
const KR_TRADE_FLOOR = 10;          // headroom reserved for a sweep penalty
// #1864: bound the soft pace so a burst ack stays sub-500ms — the mirror may
// still be pessimistic vs the venue; past this we send anyway (flagged
// paced) and let the venue's own limiter be the truth.
const KR_ORDER_PACE_MAX_MS = 400;   // adds soft-defer at most this, then send
// Cancel age-penalty schedule (Kraken docs, seconds since the order was
// placed → extra points). Unknown age = worst case (cautious mirror).
function krCancelPenalty(ageS) {
  const a = Number(ageS);
  if (!(a >= 0)) return 8;
  if (a < 5) return 8;
  if (a < 10) return 6;
  if (a < 15) return 5;
  if (a < 45) return 4;
  if (a < 90) return 2;
  if (a < 300) return 1;
  return 0;
}
function krTradeLedgerNew(now) { return { pts: KR_TRADE_MAX, ts: Number(now) || 0 }; }
function krTradeRefill(L, now) {
  const dt = Math.max(0, (Number(now) || 0) - L.ts) / 1000;
  L.pts = Math.min(KR_TRADE_MAX, L.pts + dt * KR_TRADE_DECAY);
  L.ts = Number(now) || 0;
}
// Spend unconditionally (cancels/sweeps ride this — never blocked; mirror
// clamps at 0 like the query ledger). Returns pts AFTER the spend.
function krTradeSpend(L, cost, now) {
  krTradeRefill(L, now);
  L.pts = Math.max(0, L.pts - (Number(cost) || 0));
  return L.pts;
}
// Soft gate for order ADDS: below the reserved floor the add waits a bounded
// beat (never longer than KR_ORDER_PACE_MAX_MS) and then sends ANYWAY,
// flagged paced — an order is never refused by the mirror, cancels just
// always keep headroom. { send:true } or { send:true, waitMs, paced:true }.
function krTradeGate(L, cost, now) {
  krTradeRefill(L, now);
  if (L.pts - cost >= KR_TRADE_FLOOR) return { send: true };
  const need = (KR_TRADE_FLOOR + cost) - L.pts;
  const waitMs = Math.min(KR_ORDER_PACE_MAX_MS,
                          Math.ceil((need / KR_TRADE_DECAY) * 1000));
  return { send: true, waitMs: waitMs, paced: true };
}
function krTradePts(L, now) {
  const dt = Math.max(0, (Number(now) || 0) - L.ts) / 1000;
  return Math.min(KR_TRADE_MAX, L.pts + dt * KR_TRADE_DECAY);
}

// --- #1864 fills-first local position math (pure) ----------------------------
// The posrow must move the instant an execution lands — not when Kraken's
// balances echo (~3-6s late) or the REST auditor catches up. Every live
// executions `trade` row applies its balance delta to the WS totals map
// synchronously: buy = +base / -(cost+fee), sell = -base / +(cost-fee); fees
// subtract from their own asset rows. Values stay strings (WS balances
// shape). Returns the list of touched asset names ([] = row not applicable)
// so the caller can stamp per-asset touch times for the auditor grace.
// #1884: the optional `dirs` map additionally records each touched asset's
// last fill DIRECTION ({ ts, d: ±1 }) — the auditor's regression clamp keys
// on it (a stale REST page must never move a recently-filled asset BACK
// against the fill's direction; the short 2.5s touch grace alone missed
// pages that landed a few seconds later: observed qty 1194→796→1194).
function krFillTotalsApply(totals, e, dirs, now) {
  if (!totals || !e || typeof e !== 'object') return [];
  if (String(e.exec_type || '') !== 'trade') return [];
  const sym = String(e.symbol || '');
  const base = sym.split('/')[0], quote = sym.split('/')[1] || '';
  const qty = Number(e.last_qty), px = Number(e.last_price);
  if (!base || !quote || !(qty > 0)) return [];
  const cost = (e.cost != null && Number.isFinite(Number(e.cost)))
    ? Number(e.cost) : (px > 0 ? qty * px : NaN);
  if (!Number.isFinite(cost)) return [];
  const buy = String(e.side || '').toLowerCase() === 'buy';
  const touched = {};
  const add = (asset, d) => {
    if (!asset || !Number.isFinite(d)) return;
    const cur = Number(totals[asset]);
    totals[asset] = String((Number.isFinite(cur) ? cur : 0) + d);
    touched[asset] = 1;
    if (dirs && d !== 0) dirs[asset] = { ts: Number(now) || 0, d: d > 0 ? 1 : -1 };
  };
  add(base, buy ? qty : -qty);
  add(quote, buy ? -cost : cost);
  for (const f of (Array.isArray(e.fees) ? e.fees : [])) {
    if (f && f.asset != null) add(String(f.asset), -Number(f.qty));
  }
  return Object.keys(touched);
}
// Background auditor (BalanceEx / WS balances vs the local fill-applied
// totals): venue snapshots may PREDATE a just-applied fill, so assets whose
// local row was fill-touched within graceMs keep the LOCAL value; everything
// else takes the audit value, and any real divergence (relative diff beyond
// eps on a non-grace asset) is reported so the override is diag-visible —
// "corrects on true divergence", never a silent stale clobber.
const KR_FILL_TOUCH_GRACE_MS = 2500;
const KR_AUDIT_REL_EPS = 1e-9;
// #1884 regression clamp window: a REST page fetched under budget deferral
// can land several seconds after the fill that moved an asset — within this
// window an audit value that moves the asset AGAINST the last fill's
// direction (buy-increased asset shrinking / sell-reduced asset growing) is
// provably stale and keeps the LOCAL value (clamp list → kr_audit_clamp
// diag). Corrections IN the fill's direction still apply.
const KR_FILL_CLAMP_GRACE_MS = 15000;
function krTotalsAudit(local, audit, touch, now, graceMs, eps, dirs, clampMs) {
  const g = (graceMs == null) ? KR_FILL_TOUCH_GRACE_MS : graceMs;
  const e = (eps == null) ? KR_AUDIT_REL_EPS : eps;
  const cg = (clampMs == null) ? KR_FILL_CLAMP_GRACE_MS : clampMs;
  const out = {}, div = [], clamp = [];
  const keys = {};
  for (const k of Object.keys(audit || {})) keys[k] = 1;
  for (const k of Object.keys(local || {})) keys[k] = 1;
  for (const a of Object.keys(keys)) {
    const fresh = touch && touch[a] != null && (now - touch[a]) <= g;
    const lv = local && local[a] != null ? Number(local[a]) : null;
    const av = audit && audit[a] != null ? Number(audit[a]) : null;
    if (fresh && lv != null) { out[a] = String(local[a]); continue; }
    // #1884: direction-aware regression clamp (see KR_FILL_CLAMP_GRACE_MS)
    const dr = dirs && dirs[a];
    if (dr && lv != null && (now - dr.ts) <= cg &&
        ((dr.d > 0 && (av == null || av < lv - e * Math.max(1, Math.abs(lv)))) ||
         (dr.d < 0 && av != null && av > lv + e * Math.max(1, Math.abs(lv))))) {
      // #1890 clamp-once: the FIRST disagreement inside the window keeps the
      // local value (a REST page fetched pre-fill is genuinely stale). A
      // SECOND consecutive audit disagreeing in the same direction means the
      // venue is telling the truth — a double-ingested fill looks exactly
      // like a "regression", and the old unconditional clamp latched the
      // inflated qty until the window expired (sell-all kept failing).
      if (!((dr.c | 0) >= 1)) {
        dr.c = (dr.c | 0) + 1;
        out[a] = String(local[a]);
        clamp.push(a);
        continue;
      }
    } else if (dr) dr.c = 0;   // #1890: agreement/in-direction move resets the tie counter
    if (av == null) {         // local-only asset past grace: auditor wins (drop)
      if (lv != null && Math.abs(lv) > e) div.push(a);
      continue;
    }
    out[a] = String(audit[a]);
    if (lv == null || Math.abs(lv - av) > e * Math.max(1, Math.abs(av))) div.push(a);
  }
  return { totals: out, div: div, clamp: clamp };
}
// Bounded prune for the per-asset fill-touch map (entries expire with the
// grace window; the map only ever holds a scalp session's active assets).
function krFillTouchPrune(touch, now, graceMs) {
  const g = (graceMs == null) ? KR_FILL_TOUCH_GRACE_MS : graceMs;
  for (const a of Object.keys(touch || {})) {
    if (!(now - touch[a] <= g)) delete touch[a];
  }
}
// #1884: same bounded-map rule for the fill-direction map (clamp window).
function krFillDirsPrune(dirs, now, clampMs) {
  const g = (clampMs == null) ? KR_FILL_CLAMP_GRACE_MS : clampMs;
  for (const a of Object.keys(dirs || {})) {
    if (!(now - (dirs[a] && dirs[a].ts) <= g)) delete dirs[a];
  }
}

// GET /derivatives/api/v3/openpositions → common position rows (sizes BASE,
// PF_ contractSize 1 — kr_row_from_fut_pos parity; no mark on Kraken rows).
function krPositionRows(data) {
  const rows = [];
  for (const p of ((data || {}).openPositions || [])) {
    try {
      const sz = bnNum((p || {}).size);
      if (sz == null || Number(sz) === 0) continue;
      rows.push({
        symbol: p.symbol,
        side: String(p.side || '').toLowerCase() === 'long' ? 'Buy' : 'Sell',
        size: sz,
        mark: null,
      });
    } catch (e) { /* skip bad row */ }
  }
  return rows;
}

// int(Decimal(s)) parity — truncate a decimal string toward zero → Number.
function truncInt(s) {
  const d = decNorm(s);
  const whole = d.digits / (10n ** BigInt(d.scale));
  return Number((d.neg ? '-' : '') + whole.toString());
}

// urlencode parity is NOT required cross-language — the signature is always
// computed over the SAME string that is sent (self-consistent per request).
function formEnc(pairs) {
  return (pairs || []).map(function (kv) {
    return encodeURIComponent(String(kv[0])) + '=' +
      encodeURIComponent(String(kv[1])).replace(/%20/g, '+');
  }).join('&');
}

// ---------------------------------------------------------------------------
// acct_read rate-limit guard + single-flight (#1724) — pure, node-tested.
// The panel polls native account reads per venue at a budget-audited cadence
// (panel TERM_ACCT_POLL_VENUE_MS), but rate-limit hits can still arrive
// (external tools sharing the key, native trading bursts on the same key/IP,
// multiple windows). This shared guard wraps EVERY venue's acct_read:
//   1. cool-down gate: after a venue signals rate-limiting, further reads
//      short-circuit here (no HTTP) until the venue-specific cool-down ends,
//      returning { ok:false, rateLimited:true, retryInMs } so the panel can
//      show the amber "paced" state instead of the red error chip;
//   2. single-flight + short memo per venue+account: concurrent reads from
//      multiple boards/windows share ONE in-flight promise, and a read
//      landing within ACCT_READ_MEMO_MS reuses the last result — N windows
//      cost the venue exactly one request train per poll tick.
// NEVER a silent server fallback — failures stay visible (fail-visible rule).
// Venue cool-downs sized to documented budgets (see panel poll-map audit):
// slower-recovering counters (Kraken spot decay 0.33-0.5/s, Binance ban
// escalation) cool longer than plain per-second limiters.
const ACCT_RL_COOLDOWN_MS = {
  bybit: 10000, okx: 10000, bitget: 10000,
  phemex: 15000, gate: 15000, kucoin: 15000, asterdex: 15000,
  mexc: 20000, bitmex: 20000,
  binance: 30000, kraken: 30000,
};
const ACCT_RL_MAX_MS = 120000;
const ACCT_READ_MEMO_MS = 1200;
// #2281 union pacing. The panel applies its budget-audited per-venue cadence
// PER WINDOW, but a venue only ever sees the UNION of every window's polls
// through this one process — with five terminal windows open the 1200 ms memo
// deduped almost nothing (field capture 2026-08-16: every venue converged on
// ~0.49 reads/s regardless of whether its audited cadence was 2.5 s or 10 s,
// 5,495 reads in 1,042 s). A caller may now declare the cadence it is polling
// at (intent.memoMs, additive — an old panel keeps the 1200 ms default byte
// for byte) so N windows really do cost the venue ONE request train per
// cadence. Clamped: never below the old default, never above the ceiling, and
// checked against the CALLER's own value so the fastest-demanding window
// still gets its full freshness.
const ACCT_READ_MEMO_MAX_MS = 20000;
function acctMemoMs(intent) {
  const m = intent && Number(intent.memoMs);
  if (!Number.isFinite(m) || !(m > 0)) return ACCT_READ_MEMO_MS;
  return Math.min(Math.max(m, ACCT_READ_MEMO_MS), ACCT_READ_MEMO_MAX_MS);
}
// #2281 shared-pool admission caps. Field capture 2026-08-16 (15 windows, 11
// venues, 17.4 min): AVERAGE outbound concurrency was only 2.29 requests, but
// the per-window metronomes align and every venue fires together — the same
// session peaked at 43 simultaneous in-flight TLS requests and spent whole 6 s
// stretches above 20. Everything (including each renderer's own /state poll)
// funnels through one tunnel, so those bursts queue the user-visible path
// behind background refresh and every window wedges at once (17 stalls, all
// 6.0-7.0 s, several simultaneous across five windows). Admitting at most
// ACCT_POOL_MAX_TOTAL costs nothing at a 2.29 average and removes the spikes.
const ACCT_POOL_MAX_TOTAL = 6;
// Per-venue share is HARD: a venue whose reads hang can never occupy more than
// this, so a slow venue degrades ONLY its own data.
const ACCT_POOL_MAX_VENUE = 2;
// …and the GLOBAL cap is soft after this bound: a waiter queued longer than
// ACCT_POOL_OVERFLOW_MS is admitted regardless of the total, so a wedged venue
// sitting on its own slots can never stall the other ten.
const ACCT_POOL_OVERFLOW_MS = 4000;
// #2131 hot-venue priority: a venue where the user JUST traded (own fill /
// order event / gesture — markHot below, or an intent stamped prio:'hot' by
// the panel) is HOT for ACCT_HOT_MS. HOT reads jump ahead of routine
// idle-venue polls at the shared dispatch gate (acctPrioGate) and may bypass
// a memo entry an idle poll populated — NEVER the venue rate budget: the
// cool-down gate stays first and unconditional, and single-flight still
// coalesces concurrent reads, so request volume never exceeds today's caps.
const ACCT_HOT_MS = 60000;
// Idle reads yield to pending HOT reads at most this long (bounded — a hung
// hot read must never starve idle venues forever).
const ACCT_IDLE_YIELD_MS = 1500;
// Priority dispatch gate (pure factory, injectable clock — node-tested).
// hot enter() is immediate; idle enter() waits while any hot read is being
// dispatched/in flight, capped at yieldMs. Returns the queued-wait ms so the
// diag line can split queue wait from HTTP time.
function acctPrioGate(nowFn, yieldMs) {
  const now = typeof nowFn === 'function' ? nowFn : Date.now;
  const cap = (Number.isFinite(yieldMs) && yieldMs > 0) ? yieldMs : ACCT_IDLE_YIELD_MS;
  let hotN = 0;
  let waiters = [];
  const release = () => {
    if (hotN > 0) return;
    const w = waiters; waiters = [];
    for (const f of w) { try { f(); } catch (e) { /* resolved */ } }
  };
  return {
    hotPending: () => hotN,
    // Returns a NUMBER (0) synchronously when there is nothing to wait for —
    // the guard's uncontended path must stay synchronous (the single-flight
    // timing existing tests pin) — and a promise only under hot contention.
    enter: (isHot) => {
      if (isHot) { hotN++; return 0; }
      if (hotN === 0) return 0;
      return (async () => {
        const t0 = now();
        while (hotN > 0 && now() - t0 < cap) {
          await new Promise((res) => {
            waiters.push(res);
            setTimeout(res, 50);   // escape hatch — never deadlock
          });
        }
        return now() - t0;
      })();
    },
    exit: (isHot) => { if (isHot) { hotN = hotN > 0 ? hotN - 1 : 0; release(); } },
  };
}
// #2281 shared-pool admission gate (pure factory, injectable clock — node-
// tested). acctPrioGate above only ORDERS dispatch; nothing bounded how many
// account reads were on the wire at once, and the answer in the field was 43.
// Three rules:
//   * per-venue cap is HARD — one venue can never occupy more than its share,
//     so a hanging venue degrades only its own data;
//   * the global cap is soft past overflowMs — a waiter queued longer than the
//     bound is admitted anyway, so a wedged venue can never stall the others;
//   * hot waiters (the venue the user is trading) are granted before idle
//     background refresh, and a waiter blocked by ITS venue's cap is skipped
//     over rather than blocking the queue behind it.
// Admission REORDERS and paces; it never sheds a read and never changes what
// is requested. Trading paths (order/cancel/fills) do not ride this gate at
// all — only the background account-read lane does.
function acctPoolGate(nowFn, opts) {
  const now = typeof nowFn === 'function' ? nowFn : Date.now;
  const o = opts || {};
  const pick = (v, d) => (Number.isFinite(v) && v > 0) ? v : d;
  const maxTot = pick(o.maxTotal, ACCT_POOL_MAX_TOTAL);
  const maxVen = pick(o.maxVenue, ACCT_POOL_MAX_VENUE);
  const ovMs = pick(o.overflowMs, ACCT_POOL_OVERFLOW_MS);
  let tot = 0;
  const per = {};                  // venue → in-flight count
  const qHot = [], qIdle = [];     // waiters, FIFO within tier
  const vN = (v) => per[v] || 0;
  const take = (v) => { tot++; per[v] = vN(v) + 1; };
  const free = (v) => (vN(v) < maxVen) && (tot < maxTot);
  const grant = (w) => {
    if (w.done) return;
    w.done = true;
    if (w.tm) { try { clearTimeout(w.tm); } catch (e) { /* noop */ } w.tm = null; }
    take(w.v);
    try { w.res(Math.max(0, now() - w.t0)); } catch (e) { /* already settled */ }
  };
  // A waiter past the overflow bound ignores the GLOBAL cap only — the
  // per-venue cap is never waived.
  const admit = (w) => (vN(w.v) < maxVen) && (tot < maxTot || (now() - w.t0) >= ovMs);
  const pump = () => {
    for (const q of [qHot, qIdle]) {
      for (let i = 0; i < q.length; ) {
        const w = q[i];
        if (w.done) { q.splice(i, 1); continue; }
        if (!admit(w)) { i++; continue; }   // venue-capped → skip, never block the queue
        q.splice(i, 1);
        grant(w);
      }
    }
  };
  const wait = (v, isHot) => new Promise((res) => {
    const w = { v: v, t0: now(), res: res, done: false, tm: null };
    (isHot ? qHot : qIdle).push(w);
    // Overflow escape hatch: without a release nothing would re-check the
    // bound, so arm one timer per waiter (cleared on grant, unref'd so it can
    // never hold the process open).
    try {
      w.tm = setTimeout(() => { w.tm = null; pump(); }, ovMs + 25);
      if (w.tm && typeof w.tm.unref === 'function') w.tm.unref();
    } catch (e) { /* timers unavailable — release still pumps */ }
  });
  return {
    // Returns a NUMBER (0) synchronously when a slot is free — the guard's
    // uncontended path must stay synchronous (single-flight timing) — and a
    // promise resolving to the queued-wait ms only under contention.
    acquire: (venue, isHot) => {
      const v = String(venue || '');
      if (free(v)) { take(v); return 0; }
      return wait(v, !!isHot);
    },
    release: (venue) => {
      const v = String(venue || '');
      if (tot > 0) tot--;
      if (per[v] > 0) { per[v]--; if (!per[v]) delete per[v]; }
      pump();
    },
    // Diag/testing surface: in-flight totals at this instant.
    depth: () => ({ tot: tot, v: Object.assign({}, per),
                    wait: qHot.length + qIdle.length }),
    pump: pump,
  };
}
// One read outcome → was it a rate-limit? Explicit flag (wrappers that parse
// Retry-After) or the uniform "Rate limited by <venue>" message every venue
// wrapper emits for 429 statuses AND body-code maps (OKX 50011, KuCoin
// 429000, Bybit 10006/10018, Binance -1003, Gate TOO_MANY_REQUESTS,
// Bitget 429, MEXC 510, Phemex 10004/39995).
function acctRlHit(r) {
  if (!r || r.ok) return false;
  if (r.rateLimited) return true;
  return /rate limit|too many request/i.test(String(r.message || ''));
}
// Cool-down for one venue: an explicit venue hint (Retry-After ms) wins,
// else the per-venue table, else a 15s default; capped at ACCT_RL_MAX_MS.
function acctRlWaitMs(venue, hintMs) {
  if (Number.isFinite(hintMs) && hintMs > 0) return Math.min(hintMs, ACCT_RL_MAX_MS);
  const c = ACCT_RL_COOLDOWN_MS[String(venue || '')];
  return (Number.isFinite(c) && c > 0) ? c : 15000;
}
// Guard factory: wraps the raw per-venue dispatcher. Pure state machine over
// an injectable clock so the dedup/backoff behavior is node-testable.
// Optional onEvent(ev, info) diagnostic tap (#1786): 'paced' (cool-down
// short-circuit), 'memo' (fresh-result reuse), 'coalesced' (joined an
// in-flight train). Injected, never required — the guard stays pure.
function acctReadGuard(runRaw, nowFn, onEvent) {
  const now = typeof nowFn === 'function' ? nowFn : Date.now;
  const emit = (ev, info) => {
    if (typeof onEvent !== 'function') return;
    try { onEvent(ev, info); } catch (e) { /* diagnostics never break reads */ }
  };
  const rlUntil = {};    // venue → cool-down end ts
  const inflight = {};   // venue|credSlot → in-flight promise
  const memo = {};       // venue|credSlot → { ts, r, hot }
  const hotAt = {};      // #2131: venue → last own-trade-activity ts
  const gate = acctPrioGate(now);   // #2131: hot-first dispatch ordering
  const pool = acctPoolGate(now);   // #2281 shared-pool admission caps
  let readSeq = 0;       // #1853: monotonic ISSUANCE seq stamped on results
  const guarded = async function (intent) {
    const venue = String((intent && intent.venue) || '');
    const key = venue + '|' + String((intent && intent.credSlot) || venue);
    const t0 = now();
    // #2131: HOT = panel-stamped prio:'hot' (gesture/push panel-side) OR a
    // shell-observed own trade/push event within ACCT_HOT_MS (markHot below).
    const isHot = (intent && intent.prio === 'hot') ||
                  (t0 - (hotAt[venue] || 0) < ACCT_HOT_MS);
    if (intent && intent.prio === 'hot') hotAt[venue] = t0;
    // Cool-down gate stays FIRST and unconditional — priority never bypasses
    // the venue rate budget (#2131 rule: reorder, never add volume).
    const left = (rlUntil[venue] || 0) - t0;
    if (left > 0) {
      emit('paced', { venue: venue, retryInMs: left });
      return { ok: false, rateLimited: true, retryInMs: left,
               message: 'Rate limited — pacing reads, retry in ' + Math.ceil(left / 1000) + 's' };
    }
    const m = memo[key];
    // #2131: a HOT read must not be served a stale memo an IDLE poll just
    // populated — hot reuses only hot-stamped memo entries; idle reads keep
    // the full memo window byte-identically.
    if (m && t0 - m.ts < acctMemoMs(intent) && (!isHot || m.hot)) {   // #2281 caller cadence
      emit('memo', { venue: venue }); return m.r;
    }
    if (inflight[key]) { emit('coalesced', { venue: venue }); return await inflight[key]; }
    // #1853 snapshot ordering: stamp ISSUANCE order (seq taken BEFORE the
    // request goes out — a read issued earlier captured older venue state
    // even if its response settles later) so the panel can discard a slow
    // stale read that lands after a fresher one already applied (live diag:
    // five overlapped kraken reads completed together, ms 3302…53 — the
    // 5.4s-old snapshot overwrote the 53ms one and blanked the posrow).
    // Memo/coalesced callers share the stamp — same snapshot, same seq.
    const issSeq = ++readSeq;
    const p = (async () => {
      // #2131: idle reads yield (bounded) while hot reads dispatch; the
      // queued-wait ms is stamped separately from HTTP time for the diag.
      // gate.enter returns 0 SYNCHRONOUSLY when uncontended so the raw call
      // keeps firing on the same tick (single-flight timing unchanged).
      const qe = gate.enter(isHot);
      const q1 = (typeof qe === 'number') ? qe : await qe;
      // #2281 admission: bounded share of the shared outbound pool. Same
      // synchronous-when-free contract as the priority gate above, so an
      // uncontended read still fires on this tick.
      const pe = pool.acquire(venue, isHot);
      const q2 = (typeof pe === 'number') ? pe : await pe;
      const qms = q1 + q2;
      const dep = pool.depth();
      const dispT = now();
      let r;
      try {
        // __hot rides the intent copy so venue readers can claim priority on
        // their own internal budgets (kraken rate-points ledger) — additive,
        // the original intent object is never mutated.
        r = await runRaw(isHot ? Object.assign({}, intent, { __hot: 1 }) : intent);
      } finally { gate.exit(isHot); pool.release(venue); }
      if (r && typeof r === 'object') {
        if (r.readSeq == null) r.readSeq = issSeq;
        if (r.prio == null) r.prio = isHot ? 'hot' : 'idle';   // #2131 diag
        if (r.qms == null && Number.isFinite(qms)) r.qms = Math.round(qms);
        // #2281: pool depth AT DISPATCH — the gauge that identifies pool
        // saturation in a capture without guessing it from overlapping spans.
        if (r.inf == null) r.inf = dep.tot;
        if (r.qw == null && dep.wait > 0) r.qw = dep.wait;
        // #2281: the snapshot's true age. A memo hit hands this same object to
        // a window that asked up to memoMs later, and a reader that stamps its
        // push-overlay boundary at its OWN call time would then consume frames
        // the snapshot never contained. Dispatch time is the conservative
        // boundary (earlier ⇒ overlays survive rather than vanish).
        if (r.snapTs == null) r.snapTs = dispT;
      }
      if (acctRlHit(r)) {
        const wait = acctRlWaitMs(venue, Number.isFinite(r.retryInMs) ? r.retryInMs : null);
        rlUntil[venue] = now() + wait;
        r.rateLimited = true;
        if (!(Number.isFinite(r.retryInMs) && r.retryInMs > 0)) r.retryInMs = wait;
      }
      return r;
    })();
    inflight[key] = p;
    try {
      const r = await p;
      memo[key] = { ts: now(), r: r, hot: isHot };
      return r;
    } finally { delete inflight[key]; }
  };
  // #1826: trade acks invalidate the memoized VALUE for one venue+account so
  // the next read reflects the optimistic echo instead of a pre-ack snapshot.
  // Single-flight state is untouched — concurrent reads keep coalescing.
  guarded.bust = function (venue, credSlot) {
    delete memo[String(venue || '') + '|' + String(credSlot || venue || '')];
    emit('bust', { venue: String(venue || '') });
  };
  // #2131: own trade activity observed shell-side (trade ack, push event)
  // marks the venue HOT for ACCT_HOT_MS — its reads dispatch first and skip
  // idle-populated memo entries. Never touches cool-downs or single-flight.
  guarded.markHot = function (venue) {
    const v = String(venue || '');
    if (!v) return;
    hotAt[v] = now();
    emit('hot', { venue: v });
  };
  guarded.isHot = function (venue) {
    return now() - (hotAt[String(venue || '')] || 0) < ACCT_HOT_MS;
  };
  return guarded;
}

// #2230 PUBLIC-data share guard — pure, node-tested (the catalog twin of
// acctReadGuard). Every window builds its own catalog/ticker caches, so N open
// windows used to fetch, read and parse the SAME multi-megabyte payload N
// times on the ONE main-process loop that serves every window's IPC and WS
// traffic (field log 2026-08-15: Binance spot exchangeInfo 6.67 MB fetched 5×
// inside 2 s, Phemex products 2.5 MB 5×, the 30 s 24h-ticker sweep 4× inside
// 1.1 s — ~96 MB of boot burst). Two rules, both required:
//   1. single-flight — concurrent callers for the same request JOIN the one
//      in-flight promise (the app fetches it once, the venue sees one request);
//   2. freshness window STAMPED AT REQUEST START (not after the body lands and
//      parses): a window arriving moments later reuses the result, and the
//      window can never be extended by a slow fetch. This is exactly the bug
//      in the old phemexProducts TTL — it stamped after the parse, so five
//      concurrent callers all missed and all fetched.
// Only sizeable bodies are memoized (small live reads — tape, ticker/price,
// kline tails — keep byte-identical per-call freshness and merely coalesce),
// and ONLY successful ones: an error is never cached (fail-open, never a
// latched failure — memory venue-relay-fallback).
const CAT_SHARE_MEMO_MS = 10000;
const CAT_SHARE_MIN_BYTES = 256 * 1024;
// Body size of a bridge reply, 0 when it must not be memoized.
function catShareBytes(r) {
  if (!r || typeof r !== 'object' || r.ok !== true) return 0;
  if ((r.status | 0) !== 200) return 0;
  if (typeof r.body === 'string') return r.body.length;
  if (typeof r.text === 'string') return r.text.length;
  return 0;
}
function catShareGuard(nowFn, onEvent, opts) {
  const now = typeof nowFn === 'function' ? nowFn : Date.now;
  const o = opts || {};
  const memoMs = (Number.isFinite(o.memoMs) && o.memoMs > 0) ? o.memoMs : CAT_SHARE_MEMO_MS;
  const minBytes = (Number.isFinite(o.minBytes) && o.minBytes >= 0) ? o.minBytes : CAT_SHARE_MIN_BYTES;
  const sizeOf = (typeof o.sizeOf === 'function') ? o.sizeOf : catShareBytes;
  const emit = (ev, info) => {
    if (typeof onEvent !== 'function') return;
    try { onEvent(ev, info); } catch (e) { /* diagnostics never break reads */ }
  };
  const inflight = {};   // key → in-flight promise
  const memo = {};       // key → { t0 (REQUEST START), r, n }
  // EVERY caller gets its OWN top-level object. The shared thing is the body
  // STRING (immutable, so sharing it is free); the wrapper is not, because the
  // att:trade-exec handler stamps per-call fields onto the reply it returns
  // (`via`, socket-reuse marker). Handing two windows the same object would
  // silently give the second one the first one's transport label.
  const out = (r) => ((r && typeof r === 'object' && !Array.isArray(r)) ? Object.assign({}, r) : r);
  const share = async function (key, run, info) {
    const k = String(key || '');
    const t0 = now();
    const m = memo[k];
    if (m) {
      if (t0 - m.t0 < memoMs) { emit('memo', Object.assign({ k: k, n: m.n }, info)); return out(m.r); }
      delete memo[k];
    }
    if (inflight[k]) { emit('coalesced', Object.assign({ k: k }, info)); return out(await inflight[k]); }
    const p = (async () => await run())();
    inflight[k] = p;
    try {
      const r = await p;
      const n = sizeOf(r);
      // Stamped with t0 — the REQUEST START, never the settle time.
      if (n >= minBytes) memo[k] = { t0: t0, r: r, n: n };
      return out(r);
    } finally { delete inflight[k]; }
  };
  share.stats = () => ({ memo: Object.keys(memo).length, inflight: Object.keys(inflight).length });
  return share;
}

// ---------------------------------------------------------------------------
// Runtime wiring (electron main). Everything below touches the network /
// disk / IPC and is exercised only inside the shell.
// ---------------------------------------------------------------------------
function createTradeNative(opts) {
  const ipcMain = opts.ipcMain;
  const safeStorage = opts.safeStorage;
  const getProxyConfig = opts.getProxyConfig;
  const senderOk = opts.senderOk;              // top-level app-origin frame gate
  const userDataDir = opts.userDataDir;        // function → app.getPath('userData')
  // Admin diagnostic tap (#1786) — optional; no-op when absent (regular users).
  // HARD RULE at every call site below: only secret-free summaries are passed
  // (host/path/method/status/ms/row counts) — NEVER headers, query strings
  // (they carry signatures), bodies, or creds. The logger sanitizes again.
  const diagTap = typeof opts.diag === 'function' ? opts.diag : null;
  // #1867 push channel sink — main.js broadcasts each event to every panel
  // window ('att:ledger-push'). Absent (old wiring) → the channel is inert.
  const pushLedgerCb = typeof opts.pushLedger === 'function' ? opts.pushLedger : null;
  function tdiag(cat, ev, data) {
    if (!diagTap) return;
    try { diagTap(cat, ev, data); } catch (e) { /* diagnostics never break trading */ }
  }
  // --- main-loop phase timers (#2234) ---------------------------------------
  // Freeze round 6 could only place a stall in a NEIGHBOURHOOD ("30-100 ms
  // after a push flush, an account memo bust and a blotter ingest"). These
  // taps name each phase of the fill/push path separately so the next field
  // log attributes a stall to one phase. Costs one boolean test when the
  // admin diag gate is off, which is every non-admin run.
  const perfNow = (typeof performance !== 'undefined' && performance && performance.now)
    ? () => performance.now() : () => Date.now();
  const LB_PERF_FLUSH_MS = 2500;   // under the diag limiter's 30/min per cat|ev|k
  let _lbPerf = null, _lbPerfT = 0;
  function lbT() { return diagTap ? perfNow() : 0; }
  function lbTap(phase, t0) {
    if (!diagTap || !t0) return;
    const ms = perfNow() - t0;
    if (!_lbPerf) { _lbPerf = lbPerfNew(); _lbPerfT = Date.now(); }
    lbPerfAdd(_lbPerf, phase, ms);
    if (Date.now() - _lbPerfT >= LB_PERF_FLUSH_MS) lbPerfFlush();
  }
  function lbPerfFlush() {
    if (!_lbPerf || !_lbPerf.n) { _lbPerf = null; return; }
    const P = _lbPerf;
    _lbPerf = null; _lbPerfT = Date.now();
    // `srt` = whole-store sorts in this window. It must stay 0 in steady
    // state: fills arrive in time order, so a merge appends (#2234).
    tdiag('lblot', 'phase', { k: 'lb', n: P.n, ms: P.ms, mx: P.mx,
                              srt: P.srt || undefined });
  }
  // A store sort is a COUNT, not a duration (its time already lands in
  // drain.merge) — the field log needs to see whether it happens at all.
  function lbPerfSort() {
    if (!diagTap) return;
    if (!_lbPerf) { _lbPerf = lbPerfNew(); _lbPerfT = Date.now(); }
    _lbPerf.srt = (_lbPerf.srt | 0) + 1;
    _lbPerf.n++;
  }

  const credsFile = () => path.join(userDataDir(), 'trade_creds.json');

  // --- creds store (safeStorage at rest; plaintext only transiently) -------
  function credsLoadAll() {
    try {
      const d = JSON.parse(fs.readFileSync(credsFile(), 'utf8'));
      return (d && typeof d === 'object' && d.venues && typeof d.venues === 'object') ? d.venues : {};
    } catch (e) { return {}; }
  }
  function credsSaveAll(venues) {
    try {
      fs.writeFileSync(credsFile(), JSON.stringify({ v: 1, venues: venues }));
      return true;
    } catch (e) { return false; }
  }
  function credsSet(venue, creds) {
    if (!safeStorage || !safeStorage.isEncryptionAvailable()) {
      return { ok: false, error: 'encryption-unavailable' };
    }
    const key = String(creds.key || ''), secret = String(creds.secret || '');
    // Kraken dual-pair creds: key/secret = spot pair, additive key2/secret2
    // = futures pair (separate keys — spot keys can't sign the futures API).
    // Valid when at least ONE complete pair is present.
    const key2 = String(creds.key2 || ''), secret2 = String(creds.secret2 || '');
    const dual = !!(creds.krv || key2 || secret2);
    if (dual) {
      if ((!!key !== !!secret) || (!!key2 !== !!secret2)
          || (!key && !key2)
          || key.length > 200 || secret.length > 500
          || key2.length > 200 || secret2.length > 500) {
        return { ok: false, error: 'bad-creds' };
      }
    } else if (!key || !secret || key.length > 200 || secret.length > 500) {
      return { ok: false, error: 'bad-creds' };
    }
    const payload = { key: key, secret: secret };
    if (dual) { payload.krv = 1; payload.key2 = key2; payload.secret2 = secret2; }
    if (creds.passphrase) payload.pass = String(creds.passphrase).slice(0, 200);
    let b64;
    try {
      b64 = safeStorage.encryptString(JSON.stringify(payload)).toString('base64');
    } catch (e) { return { ok: false, error: 'encrypt-failed' }; }
    const venues = credsLoadAll();
    const tailSrc = key || key2;
    venues[venue] = { b64: b64, tail: tailSrc.length >= 4 ? tailSrc.slice(-4) : tailSrc, ts: Math.floor(Date.now() / 1000) };
    if (!credsSaveAll(venues)) return { ok: false, error: 'persist-failed' };
    try { krWsCloseAll(venue); } catch (e) { /* no session */ }
    try { bnUdsClose(venue); } catch (e) { /* no session */ }
    try { hlPushClose(venue); } catch (e) { /* no session */ }
    return { ok: true, tail: venues[venue].tail };
  }
  function credsWipe(venue) {
    const venues = credsLoadAll();
    if (venue) delete venues[venue];
    credsSaveAll(venues);
    try { if (venue) krWsCloseAll(venue); else for (const k of Object.keys(krWsSessions)) krWsClose(k); } catch (e) { /* no session */ }
    try { if (venue) bnUdsClose(venue); else bnUdsCloseAll(); } catch (e) { /* no session */ }
    try { if (venue) hlPushClose(venue); else hlPushCloseAll(); } catch (e) { /* no session */ }
    try { if (venue) bybPushClose(venue); else bybPushCloseAll(); } catch (e) { /* no session */ }
    try { if (venue) gatePushClose(venue); else gatePushCloseAll(); } catch (e) { /* no session */ }
    try { if (venue) bgPushClose(venue); else bgPushCloseAll(); } catch (e) { /* no session */ }
    try { if (venue) kcPushClose(venue); else kcPushCloseAll(); } catch (e) { /* no session */ }
    return { ok: true };
  }
  function credsStatus() {
    const venues = credsLoadAll();
    const out = {};
    for (const v of TRADE_VENUES) {
      const r = venues[v];
      out[v] = r && r.b64 ? { present: true, tail: r.tail || '', ts: r.ts || 0 } : { present: false };
    }
    // Multi-account slots ('venue#aN'): report every stored composite slot so
    // the panel's per-account armed/blocked chips are truthful. Additive —
    // base-venue keys above stay byte-identical for aid-0 users.
    for (const k of Object.keys(venues)) {
      if (out[k] !== undefined) continue;
      const sn = tnSlotNorm(k);
      if (!sn || sn.slot === sn.base) continue;
      const r = venues[k];
      if (r && r.b64) out[k] = { present: true, tail: r.tail || '', ts: r.ts || 0 };
    }
    return { ok: true, venues: out, encryptionAvailable: !!(safeStorage && safeStorage.isEncryptionAvailable()) };
  }
  function credsGet(venue) {
    const r = credsLoadAll()[venue];
    if (!r || !r.b64 || !safeStorage) return null;
    try {
      const d = JSON.parse(safeStorage.decryptString(Buffer.from(r.b64, 'base64')));
      if (!d || !d.key || !d.secret) return null;
      return d;
    } catch (e) { return null; }
  }

  // --- routed HTTPS client (mirror of the native-WS agent discipline) ------
  function agentFor(route) {
    if (routeNorm(route) === 'direct') return { agent: undefined };
    const cfg = getProxyConfig();
    const proxyUrl = nativeProxyUrl(cfg);
    if (!proxyUrl) {
      if (cfg && cfg.enabled) return { refuse: true };   // unknown scheme, proxy on → refuse
      return { agent: undefined };
    }
    // Shared warm agent (keep-alive) — the SOCKS/TLS handshake is paid once
    // per proxy config, not once per request. null → refuse, same as before.
    const ag = sharedKeepAliveAgent(cfg.scheme, proxyUrl);
    if (ag) return { agent: ag };
    return { refuse: true };   // never dial direct past an enabled proxy
  }

  // Dead-socket eviction: when a reused keep-alive socket turns out dead
  // (venue/Cloudflare killed it while idle — first write fails ECONNRESET),
  // its LIFO siblings in the FREE pool are almost certainly dead too.
  // Destroy the free sockets ONLY (never in-flight ones) so the retry dials
  // a fresh tunnel instead of writing into another corpse. Same proxy route
  // — this evicts sockets, it never changes the egress.
  function evictFreeSockets(ag) {
    if (!ag || !ag.freeSockets) return;
    try {
      for (const k of Object.keys(ag.freeSockets)) {
        for (const s of (ag.freeSockets[k] || []).slice()) {
          try { s.destroy(); } catch (e2) { /* non-fatal */ }
        }
      }
    } catch (e) { /* non-fatal */ }
  }

  // Last completed request's socket-reuse flag (req.reusedSocket) — the
  // smallest honest field signal that keep-alive pooling is really working
  // on the user's route. Echoed as via.reused by att:trade-exec.
  let _lastReused = null;

  // maxBytes: optional response-body cap. Default stays 256 KB (byte-identical
  // behavior for every existing call); full-catalog GETs (Phemex
  // /public/products is ~2.5 MB and growing) MUST pass a larger cap or the
  // body silently truncates and JSON.parse fails downstream.
  // #2026 Binance IP-ban freeze registry (host → {until, boMs}) — see the
  // pure bnBan* helpers. Lives here so EVERY shell request path (time sync,
  // catalogs, tickers, listenKey keepalive, balance, klines, lblot backfill,
  // orders) shares one latch per host.
  const _bnBanReg = {};

  function httpJson(host, method, reqPath, query, bodyStr, headers, route, maxBytes, timeoutMs, deadlineAt) {
    const cap = (Number.isFinite(maxBytes) && maxBytes > 0) ? maxBytes : 262144;
    // #2281 optional per-call socket timeout + ABSOLUTE deadline. Both default
    // to absent, so every existing call site keeps HTTP_TIMEOUT_MS and one
    // full-budget retry byte-identically; only the background account-read
    // lane of a venue with a read deadline passes them. Evaluated per attempt
    // (see httpTmoAt) so the retry below cannot outlive the deadline.
    const tmoOf = () => httpTmoAt(timeoutMs, deadlineAt, Date.now());
    // #2026: while a Binance ban latch holds for this HOST, no request may
    // leave — each request during a ban EXTENDS it. Fail fast + fail visible
    // (order sends surface the ban message immediately, never queue).
    const banErr = bnBanGateErr(_bnBanReg, host, Date.now());
    if (banErr) {
      tdiag('http', 'ban-skip', { k: host, host: host, m: method, p: reqPath,
                                  until: (_bnBanReg[host] || {}).until });
      return Promise.reject(banErr);
    }
    // #2026: latch transition on every observed Binance-host response —
    // 418 (and ban-shaped 429) arms/extends the freeze, success clears it.
    const banNote = (r) => {
      if (BN_BAN_HOSTS[host]) {
        const st = bnBanRegNote(_bnBanReg, host, r.status, r.text, r.ra, Date.now());
        if (st && (r.status === 418 || r.status === 429)) {
          tdiag('http', 'ban', { k: host, host: host, s: r.status,
                                 until: st.until, boMs: st.boMs || 0 });
        }
      }
      return r;
    };
    const attempt = () => new Promise((resolve, reject) => {
      const diagT0 = Date.now();
      // #2281: the deadline is checked BEFORE a socket is opened, so an
      // expired budget costs nothing on the wire and the caller's pool slot is
      // released immediately instead of at the next transport timeout.
      const tmo = tmoOf();
      if (!(tmo > 0)) {
        const de = new Error('timeout'); de.deadline = 1; reject(de); return;
      }
      // Per-attempt transmit flag: flipped only after the request has fully
      // flushed to a live (TLS-complete) socket. An error with sent=false is
      // a connect-phase failure — nothing reached the venue.
      let sent = false;
      const ag = agentFor(route);
      if (ag.refuse) { reject(new Error('proxy-unavailable')); return; }
      const h = Object.assign({}, headers);
      // Default JSON only when the caller didn't set an explicit type
      // (Lighter sendTx is form-urlencoded).
      if (bodyStr && !h['Content-Type']) h['Content-Type'] = 'application/json';
      h['Content-Length'] = Buffer.byteLength(bodyStr || '');
      const req = https.request({
        host: host, method: method,
        path: reqPath + (query ? '?' + query : ''),
        // Direct route: use the shared keep-alive https.Agent explicitly
        // (never rely on Node's global-agent defaults) so direct requests
        // reuse warm connections exactly like proxied ones. agentFor keeps
        // returning {agent: undefined} for direct so tradeViaFromAgent's
        // proxy/direct echo stays truthful.
        agent: ag.agent !== undefined ? ag.agent : sharedKeepAliveAgent(null, null),
        headers: h, timeout: tmo,
      }, (res) => {
        let buf = '';
        res.setEncoding('utf8');
        res.on('data', (d) => { if (buf.length < cap) buf += d; });
        res.on('end', () => {
          // Field diagnosability: remember whether this request rode a warm
          // (reused) socket — surfaced via lastSocketReused() in the exec echo.
          _lastReused = !!req.reusedSocket;
          // Diag: method/host/PATH ONLY (query carries signatures), status,
          // latency, body size + truncation flag, socket reuse. Rate-limit
          // key = host so one venue's burst can't drown the others.
          tdiag('http', 'res', { k: host, host: host, m: method, p: reqPath,
                                 s: res.statusCode, ms: Date.now() - diagT0,
                                 b: buf.length, tr: buf.length >= cap,
                                 reused: !!req.reusedSocket });
          resolve({ status: res.statusCode, text: buf,
                    // #1945: truncation surfaced to callers — a body clipped
                    // at the byte cap must fail EXPLICITLY (catalog parse
                    // mysteries), never masquerade as a short-but-valid reply.
                    tr: buf.length >= cap,
                    date: (res.headers && res.headers.date) || null,
                    // #1724: Retry-After surfaced so 429 branches can hand the
                    // acct_read guard an honest venue cool-down hint.
                    ra: (res.headers && res.headers['retry-after']) || null });
        });
      });
      // 'finish' fires only after the request has been fully written to a
      // connected socket (TLS complete) — empirically it does NOT fire on
      // connect-phase failures (ECONNREFUSED / mid-TLS drops), so it is an
      // honest pre/post-transmit boundary.
      req.on('finish', () => { sent = true; });
      req.on('timeout', () => { try { req.destroy(new Error('timeout')); } catch (e) { /* noop */ } });
      req.on('error', (e) => {
        tdiag('http', 'err', { k: host, host: host, m: method, p: reqPath,
                               ms: Date.now() - diagT0, sent: sent,
                               code: (e && e.code) || '', msg: (e && e.message) || 'error' });
        try { if (e && typeof e === 'object') e.reqSent = sent; } catch (e2) {}
        reject(e);
      });
      req.end(bodyStr || '');
    });
    // Phase-aware retry (ONE retry total): connect-phase failures where the
    // body never hit the wire retry for ALL methods (incl. order POSTs — no
    // double-fill risk, nothing reached the venue); post-transmit dead-socket
    // errors keep the strict GET/DELETE-only matrix. See httpRetryAllowed.
    return attempt().then(banNote, (e) => {
      // #2281: a deadline-expired rejection is TERMINAL — the budget a retry
      // would need is already spent, so retrying could only reject again.
      if (!(e && e.deadline) && httpRetryAllowed(method, e, !!(e && e.reqSent))) {
        // Stale-socket failure → flush the agent's FREE pool first so the
        // retry is guaranteed a fresh socket (LIFO could otherwise hand it
        // another idle corpse the venue/CF killed in the same sweep).
        if (staleSocketError(e)) {
          const ag = agentFor(route);
          if (ag && ag.agent) evictFreeSockets(ag.agent);
          else if (ag && !ag.refuse) evictFreeSockets(sharedKeepAliveAgent(null, null));
        }
        return attempt().then(banNote);
      }
      throw e;
    });
  }

  // --- venue time sync (offset refreshed lazily; failure → offset 0) -------
  // One offset per venue+host (VENUE_TIME_PROBES key). Lazy: first signed
  // call probes, TTL-stamped FIRST so a dead endpoint costs one probe per
  // TTL; probe failure keeps the last offset (0 initially — old behavior).
  // Probes ride the SAME httpJson + route as the venue's orders.
  const venueClk = {};                 // probeKey → { offsetMs, ts }
  // force=true (warm-up path only) skips the fresh-return so the probe GET
  // actually rides the wire (re-warming the keep-alive socket) AND refreshes
  // the offset; the TTL stamp still updates, so signed calls stay probe-free.
  async function ensureVenueTime(venue, market, route, force) {
    const key = venueTimeProbeKey(venue, market);
    if (!key) return 0;
    const spec = VENUE_TIME_PROBES[key];
    const st = venueClk[key] || (venueClk[key] = { offsetMs: 0, ts: 0 });
    // #2012 single-flight per probe key: warm-up bursts fire force=true for
    // several signed calls at once — they all share ONE wire probe.
    if (st.inflight) return st.inflight;
    // #2012 429 backoff: while backing off, even force=true reuses the last
    // known offset (venue clocks drift slowly — stale beats hammering).
    if (clkProbeBlocked(st, Date.now())) return st.offsetMs;
    if (!force && Date.now() - st.ts < TIMESYNC_TTL_MS) return st.offsetMs;
    st.ts = Date.now();                // stamp first — one probe per TTL even on failure
    st.inflight = (async () => {
      try {
        // #2192 probe hygiene: slow samples re-sample on the now-warm socket
        // (cold-tunnel connect is one-time — the retry is fast); the fold
        // keeps the min-rtt sample and refuses to latch past CLK_RTT_SANE_MS.
        const samples = [];
        const wt0 = Date.now();
        for (let i = 0; i < CLK_PROBE_TRIES; i++) {
          // Budget enforcement (review): extra samples must FIT the remaining
          // wall budget — gate BEFORE launch and race the await against it so
          // a stalling retry can never hold signers past CLK_PROBE_BUDGET_MS.
          // The FIRST sample keeps the plain transport timeout (it is the
          // only offset source — abandoning it would leave raw clock).
          const left = CLK_PROBE_BUDGET_MS - (Date.now() - wt0);
          if (i > 0 && left < 250) break;
          const t0 = Date.now();
          let r;
          if (i === 0) {
            r = await httpJson(spec.host, 'GET', spec.path, '', null, {}, route);
          } else {
            const pr = httpJson(spec.host, 'GET', spec.path, '', null, {}, route);
            r = await Promise.race([pr,
              new Promise((rs) => setTimeout(() => rs(null), left))]);
            if (!r) {
              pr.catch(() => {});   // stray sample — never an unhandled rejection
              tdiag('clk', 'probe-slow', { k: key, venue: venue,
                                           ms: Date.now() - t0, n: i + 1, cut: 1 });
              break;
            }
          }
          const t1 = Date.now();
          if ((r.status | 0) === 429) {
            const boMs = clkProbe429(st, Date.now());
            tdiag('clk', 'probe-429', { k: key, venue: venue, boMs: boMs, n: st.boN });
            return st.offsetMs;          // keep last offset through the backoff
          }
          let sv = null;
          if (spec.dateHeader) {
            // HTTP Date header (BitMEX — no time endpoint): second resolution,
            // centered by +500ms.
            const p = r.date ? Date.parse(r.date) : NaN;
            if (isFinite(p)) sv = p + 500;
          } else {
            sv = spec.ext(JSON.parse(r.text));
          }
          samples.push({ sv: sv, t0: t0, t1: t1 });
          if (t1 - t0 <= CLK_RTT_SANE_MS) break;   // sane sample — stop early
          tdiag('clk', 'probe-slow', { k: key, venue: venue, ms: t1 - t0, n: i + 1 });
        }
        const fold = clkProbeFold(samples);
        if (fold.accept) { st.offsetMs = fold.offsetMs; clkProbeOk(st); }
        else if (fold.rtt != null) {
          // every sample slow — DO NOT latch (keep last offset); retry sooner
          // than the TTL so a recovered network re-syncs quickly.
          st.ts = Date.now() - TIMESYNC_TTL_MS + CLK_SLOW_RETRY_MS;
          tdiag('clk', 'probe-reject', { k: key, venue: venue, ms: fold.rtt,
                                         off: Math.round(fold.offsetMs) });
        }
        tdiag('clk', 'probe', { k: key, venue: venue, offsetMs: st.offsetMs,
                                ms: fold.rtt == null ? -1 : fold.rtt, n: samples.length });
      } catch (e) {
        tdiag('clk', 'probe-fail', { k: key, venue: venue, msg: (e && e.message) || 'error' });
        /* keep last offset (0 initially — engine-parity behavior) */
      }
      return st.offsetMs;
    })();
    try { return await st.inflight; } finally { st.inflight = null; }
  }
  // #2192: a timestamp rejection (-1021 class) means the cached offset is
  // poisoned (bad boot probe / PC clock jump mid-session) — zero the TTL
  // stamp so the very next ensureVenueTime re-probes (hygiene-guarded).
  // The 429 backoff state is deliberately RESPECTED: a backed-off probe
  // keeps serving the last offset instead of hammering /time.
  function clkInvalidate(venue, market) {
    const key = venueTimeProbeKey(venue, market);
    const st = key && venueClk[key];
    if (st) st.ts = 0;
    return key || null;
  }

  // --- products cache (spot base valueScale) -------------------------------
  // spotSpec THROWS on catalog fetch/parse failure (network, truncation, bad
  // JSON) and returns null ONLY for a successfully-loaded catalog that lacks
  // the symbol — the call site maps the throw to an honest "couldn't load
  // catalog" message instead of "Unknown spot symbol X".
  // The full Phemex catalog measured ~2.5 MB (2026-07); pass an 8 MB cap so
  // the default 256 KB httpJson cap doesn't silently truncate it.
  const products = { spot: null, curScales: null, raw: null, ts: 0 };
  // #2230 single-flight + START-stamped TTL. The old code stamped products.ts
  // AFTER the 2.5 MB body landed and parsed, with no in-flight guard: five
  // windows opening a Phemex board in the same second ALL saw an empty cache,
  // ALL fetched, and main parsed 12.5 MB (field log 2026-08-15). Concurrent
  // callers now join one request, and ts marks when that request STARTED so a
  // slow fetch can never stretch the freshness window.
  let _phProdInflight = null;
  async function phemexProducts(route) {
    if (products.spot && Date.now() - products.ts <= PRODUCTS_TTL_MS) return products;
    if (_phProdInflight) return await _phProdInflight;
    const t0 = Date.now();
    _phProdInflight = (async () => {
      const r = await httpJson(PHEMEX_HOST, 'GET', '/public/products', '', null, {}, route,
                               8 * 1024 * 1024);
      const d = JSON.parse(r.text);
      const data = (d && d.data) || {};
      const curScales = {};
      for (const c of data.currencies || []) {
        const vs = Number(c && c.valueScale);
        if (c && c.currency && Number.isInteger(vs) && vs >= 0 && vs <= 18) curScales[c.currency] = vs;
      }
      const spot = {};
      for (const p of data.products || []) {
        if (!p || String(p.type) !== 'Spot' || !p.symbol) continue;
        const vs = curScales[String(p.baseCurrency || '')];
        // pscale (#1713): per-symbol e-scale of spot kline prices — needed by
        // the panel's phKlineBars twin (futures rows are real numbers, 0/0).
        const ps = Number(p.priceScale);
        spot[p.symbol] = { value_scale: Number.isInteger(vs) ? vs : 8,
                           pscale: Number.isInteger(ps) && ps >= 0 ? ps : 0 };
      }
      products.spot = spot;
      products.curScales = curScales;
      products.raw = data;
      products.ts = t0;   // REQUEST START — never the post-parse settle time
      return products;
    })();
    try { return await _phProdInflight; } finally { _phProdInflight = null; }
  }
  async function spotSpec(symbol, route) {
    const p = await phemexProducts(route);
    return p.spot[symbol] || null;
  }

  // #2281: last known Phemex clock offset (0 until the first probe lands) —
  // the fallback when a deadline-bounded signer cannot wait for a slow probe.
  function phemexClkOffsetMs() {
    const k = venueTimeProbeKey('phemex', null);
    const st = k ? venueClk[k] : null;
    const o = st && Number(st.offsetMs);
    return Number.isFinite(o) ? o : 0;
  }

  // --- signed request runner ------------------------------------------------
  async function signedRequest(creds, step, route) {
    // #2281: step.deadlineAt (absolute ms) is set ONLY by the background
    // account-read lane. It bounds the WHOLE call, not just the socket: the
    // clock probe below is a wire call too, and an unbounded await here was a
    // hole through which a "7 s" read could sit on its pool slot indefinitely.
    const dlAt = Number(step.deadlineAt);
    const hasDl = Number.isFinite(dlAt) && dlAt > 0;
    let offMs;
    if (hasDl) {
      const left = dlAt - Date.now();
      if (left <= 0) return { ok: false, message: 'Phemex request timed out' };
      // Wait for the probe only as long as a probe is worth waiting for: a
      // sample slower than CLK_RTT_SANE_MS is one clkProbeFold would refuse to
      // latch anyway, so blocking the read on it buys nothing and would hand
      // the venue's whole budget to a clock probe (its own internal budget is
      // 8 s — longer than this entire read). The probe keeps running in the
      // background and lands for the NEXT read; meanwhile we sign with the
      // last known offset, exactly as this venue already does when a probe
      // fails or sits in 429 backoff. Phemex signs a 60 s EXPIRY rather than a
      // tight recvWindow, so a cold-start offset of 0 is the documented
      // initial state here, not a regression.
      const clkWait = Math.min(left, CLK_RTT_SANE_MS);
      const pr = ensureVenueTime('phemex', null, route);
      Promise.resolve(pr).catch(() => {});   // stray probe — never unhandled
      let tm = null;
      offMs = await Promise.race([
        Promise.resolve(pr).catch(() => null),
        new Promise((rs) => { tm = setTimeout(() => rs(null), clkWait); }),
      ]);
      if (tm) clearTimeout(tm);
      if (!Number.isFinite(offMs)) offMs = phemexClkOffsetMs();
    } else {
      offMs = await ensureVenueTime('phemex', null, route);
    }
    const bodyStr = step.body != null ? canonJson(step.body) : '';
    const expiry = phemexExpiry(null, offMs / 1000);
    const headers = {
      'x-phemex-access-token': creds.key,
      'x-phemex-request-signature': phemexSign(creds.secret, step.path, step.query || '', expiry, bodyStr),
      'x-phemex-request-expiry': String(expiry),
    };
    let r;
    try {
      // #2281: step.timeoutMs / step.deadlineAt are set ONLY by the background
      // account-read lane; every other caller stays undefined and keeps the
      // generic HTTP_TIMEOUT_MS with its full-budget retry.
      r = await httpJson(PHEMEX_HOST, step.method, step.path, step.query || '', bodyStr || null, headers, route,
                         undefined, step.timeoutMs, hasDl ? dlAt : undefined);
    } catch (e) {
      const em = (e && e.message) || 'error';
      if (em === 'proxy-unavailable') return { ok: false, message: 'Proxy is enabled but unavailable — order NOT sent' };
      if (em === 'timeout') return { ok: false, message: 'Phemex request timed out' };
      return { ok: false, message: 'Phemex connection error: ' + em };
    }
    if (r.status === 429) return { ok: false, message: 'Rate limited by Phemex — retry shortly' };
    if (r.status === 401) return { ok: false, message: phemexErrorMessage(401, '') };
    let data;
    try { data = JSON.parse(r.text); } catch (e) {
      return { ok: false, message: 'Phemex returned HTTP ' + r.status };
    }
    const code = data && data.code;
    if (code !== 0 && code != null) {
      return { ok: false, code: Number(code),
               message: phemexErrorMessage(code, String((data && data.msg) || '')) };
    }
    return { ok: true, data: (data && data.data !== undefined) ? data.data : data };
  }

  async function fetchPositions(creds, route) {
    const r = await signedRequest(creds, {
      method: 'GET', path: '/g-accounts/accountPositions',
      query: 'currency=USDT', body: null }, route);
    if (!r.ok) return r;
    return { ok: true, rows: phemexPositionRows(r.data || {}) };
  }


  // =========================================================================
  // Multi-venue native runtime — Binance / Bybit / OKX / Gate / Bitget.
  // Mirrors terminal_engine.py's adapters step-for-step (endpoints, retry
  // and gone-family discipline). FAIL LOUD everywhere; NO cross-transport
  // fallback and NO cross-venue request reuse.
  // =========================================================================
  const sleepMs = (ms) => new Promise((res) => setTimeout(res, ms));

  function transportFail(e, label) {
    const em = (e && e.message) || 'error';
    // #2026: a request refused by the Binance ban freeze — fail-visible with
    // the ban horizon (order attempts fail IMMEDIATELY, never queued).
    if (e && e.bnBanUntil) return { ok: false, rateLimited: true, banned: true,
                                    banUntil: e.bnBanUntil, message: em };
    if (em === 'proxy-unavailable') return { ok: false, message: 'Proxy is enabled but unavailable — order NOT sent' };
    if (em === 'timeout') return { ok: false, message: label + ' request timed out' };
    return { ok: false, message: label + ' connection error: ' + em };
  }

  // positions_find_retry parity: on a miss the snapshot is re-fetched ONCE
  // after a short delay (fresh-position REST lag).
  async function findPosRetry(fetchFn, symbol) {
    let pr = await fetchFn();
    if (!pr.ok) return pr;
    let pos = findPosition(pr.rows, symbol);
    if (!pos) {
      await sleepMs(POS_RETRY_DELAY_MS);
      pr = await fetchFn();
      if (!pr.ok) return pr;
      pos = findPosition(pr.rows, symbol);
    }
    return { ok: true, pos: pos };
  }

  // --- Binance ---------------------------------------------------------------
  function bnHost(market) { return market === 'futures' ? BINANCE_FUT_HOST : BINANCE_SPOT_HOST; }

  async function bnRequest(creds, method, market, reqPath, params, route, maxBytes, retried) {
    const offMs = await ensureVenueTime('binance', market, route);
    const q = formEnc((params || []).concat([
      ['recvWindow', String(BINANCE_RECV_WINDOW_MS)],
      ['timestamp', venueStampMs(offMs)],
    ]));
    const query = q + '&signature=' + binanceSign(creds.secret, q);
    let r;
    try {
      r = await httpJson(bnHost(market), method, reqPath, query, null,
                         { 'X-MBX-APIKEY': creds.key }, route, maxBytes);
    } catch (e) { return transportFail(e, 'Binance'); }
    if (r.status === 429 || r.status === 418) {
      // #2026: a 418 (or ban-shaped 429) has already armed the per-host
      // freeze latch inside httpJson — say BANNED, not "retry shortly", and
      // hand the acct_read guard the true freeze horizon.
      const bst = _bnBanReg[bnHost(market)];
      if (bst && bst.until > Date.now()) {
        return { ok: false, rateLimited: true, banned: true, message: bnBanMsgFor(bst),
                 code: null, retryInMs: Math.min(bst.until - Date.now(), ACCT_RL_MAX_MS) };
      }
      // #1724: honor Binance's Retry-After (seconds; 418 = IP ban escalation)
      // as an explicit cool-down hint for the acct_read guard.
      const ras = Number(r.ra);
      return { ok: false, rateLimited: true, message: 'Rate limited by Binance — retry shortly', code: null,
               retryInMs: (Number.isFinite(ras) && ras > 0) ? Math.min(ras * 1000, ACCT_RL_MAX_MS) : null };
    }
    let data = null;
    try { data = JSON.parse(r.text); } catch (e) { data = null; }
    const code = (data && typeof data.code === 'number') ? data.code : null;
    if (r.status >= 400 || (code != null && code < 0)) {
      // #2192 -1021 self-heal: a timestamp rejection means the cached clock
      // offset is poisoned — invalidate it (the retry's ensureVenueTime
      // re-probes, hygiene-guarded) and retry ONCE. A rejection is a
      // pre-execution refusal, so retrying mutations is safe; a second
      // rejection surfaces normally.
      if (!retried && clkTsReject(code, data && data.msg)) {
        tdiag('clk', 'inval', { k: clkInvalidate('binance', market),
                                venue: 'binance', code: code });
        return bnRequest(creds, method, market, reqPath, params, route, maxBytes, true);
      }
      const msg = code != null ? binanceErrorMessage(code, String((data && data.msg) || ''))
                               : 'Binance returned HTTP ' + r.status;
      return { ok: false, message: msg, code: code };
    }
    const unreadable = unreadableBodyMsg('Binance', r.status, data);
    if (unreadable) return { ok: false, message: unreadable, code: null };
    return { ok: true, data: data, code: code };
  }

  // One-way (Merged) position-mode guard — cached per key; a transient GET
  // failure is NOT cached (engine parity). Returns null when OK, else error.
  const bnOneway = {};
  async function ensureBnOneWay(creds, route) {
    const c = bnOneway[creds.key];
    const now = Date.now();
    if (c && now - c.ts < ONEWAY_TTL_MS) return c.ok ? null : c.err;
    const r = await bnRequest(creds, 'GET', 'futures', '/fapi/v1/positionSide/dual', [], route);
    if (!r.ok) return r.message;
    if (r.data && r.data.dualSidePosition) {
      const r2 = await bnRequest(creds, 'POST', 'futures', '/fapi/v1/positionSide/dual',
                                 [['dualSidePosition', 'false']], route);
      if (!r2.ok && r2.code !== -4059) {     // -4059 = "no need to change"
        const err = 'Binance account is in hedge mode and could not be switched '
                  + 'to one-way (close hedge positions first): ' + r2.message;
        bnOneway[creds.key] = { ts: now, ok: false, err: err };
        return err;
      }
    }
    bnOneway[creds.key] = { ts: now, ok: true, err: '' };
    return null;
  }

  async function bnPlace(creds, route, market, symbol, side, ordType, qty, price, clOrdID, flags) {
    const f = flags || {};
    if (market === 'futures') {
      const err = await ensureBnOneWay(creds, route);
      if (err) return { ok: false, message: err };
    }
    const typ = BN_TYPE_MAP[String(ordType).toLowerCase()] || 'LIMIT';
    if (market === 'futures' && BN_ALGO_TYPES.indexOf(typ) >= 0) {
      // Conditional (stop-family) orders live on the Algo Order API.
      const params = binanceAlgoOrderParams(symbol, side, ordType, qty, price, clOrdID, f);
      const r = await bnRequest(creds, 'POST', 'futures', '/fapi/v1/algoOrder', params, route);
      if (!r.ok) return r;
      const oid = String((r.data || {}).algoId || '');
      return { ok: true, orderID: oid || null, clOrdID: clOrdID };
    }
    const params = binanceOrderParams(market, symbol, side, ordType, qty, price, clOrdID, f);
    const reqPath = market === 'futures' ? '/fapi/v1/order' : '/api/v3/order';
    const r = await bnRequest(creds, 'POST', market, reqPath, params, route);
    if (!r.ok) return r;
    const oid = String((r.data || {}).orderId || '');
    return { ok: true, orderID: oid || null, clOrdID: clOrdID };
  }

  async function execBinance(creds, intent, route) {
    const market = intent.market === 'spot' ? 'spot' : 'futures';
    // #1943: warm the user-data streams for this slot (push-driven display)
    try { bnUdsEnsure(intent.credSlot || 'binance', creds, route); } catch (e) { /* REST-only */ }
    const bnSlot = intent.credSlot || 'binance';
    const fetchPos = async () => {
      // v3 + explicit symbol: the symbol-less v2 call returns EVERY listed
      // contract (200KB+, past the httpJson byte cap → truncated body).
      const r = await bnRequest(creds, 'GET', 'futures', '/fapi/v3/positionRisk',
                                [['symbol', String(intent.symbol)]], route);
      if (!r.ok) return r;
      return { ok: true, rows: binancePositionRows(r.data) };
    };
    if (intent.op === 'order') {
      const r = await bnPlace(creds, route, market, intent.symbol, intent.side, intent.type,
                              intent.qty, intent.price, intent.clOrdID,
                              { reduceOnly: !!intent.reduceOnly, trigger: intent.trigger });
      if (r && r.ok) { try { bnMutKick(bnSlot, market, 'order'); } catch (e) { /* push-less */ } }
      return r;
    }
    if (intent.op === 'cancel') {
      const bnCancelOk = () => {
        try { bnMutKick(bnSlot, market, 'ordgone', String(intent.orderID)); } catch (e) { /* push-less */ }
        return { ok: true, cancelled: intent.orderID };
      };
      const reqPath = market === 'futures' ? '/fapi/v1/order' : '/api/v3/order';
      const r = await bnRequest(creds, 'DELETE', market, reqPath,
                                [['symbol', intent.symbol], ['orderId', intent.orderID]], route);
      if (!r.ok && market === 'futures' && (r.code === -2011 || r.code === -2013)) {
        // Conditionals carry algoIds the plain endpoint doesn't know.
        const r2 = await bnRequest(creds, 'DELETE', 'futures', '/fapi/v1/algoOrder',
                                   [['algoId', intent.orderID]], route);
        if (r2.ok) return bnCancelOk();
        return r;                       // surface the ORIGINAL (clearer) error
      }
      if (!r.ok) return r;
      return bnCancelOk();
    }
    if (intent.op === 'cancel_all') {
      const bnSweepOk = () => {
        try { bnMutKick(bnSlot, market, 'order'); } catch (e) { /* push-less */ }
        return { ok: true, cancelled: 'all' };
      };
      if (market === 'futures') {
        const r = await bnRequest(creds, 'DELETE', 'futures', '/fapi/v1/allOpenOrders',
                                  [['symbol', intent.symbol]], route);
        if (!r.ok) return r;
        // Algo (conditional) orders are NOT swept by allOpenOrders.
        const ra = await bnRequest(creds, 'DELETE', 'futures', '/fapi/v1/algoOpenOrders',
                                   [['symbol', intent.symbol]], route);
        if (!ra.ok && ra.code !== -2011 && ra.code !== -2013) return ra;
        return bnSweepOk();
      }
      const r = await bnRequest(creds, 'DELETE', 'spot', '/api/v3/openOrders',
                                [['symbol', intent.symbol]], route);
      if (!r.ok && r.code !== -2011) return r;   // -2011 = nothing open — fine
      return bnSweepOk();
    }
    const pr = await findPosRetry(fetchPos, intent.symbol);
    if (!pr.ok) return pr;
    if (intent.op === 'close') {
      if (!pr.pos) return { ok: false, message: 'Position not found' };
      const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
      const r = await bnPlace(creds, route, 'futures', pr.pos.symbol, side, 'market',
                              pr.pos.size, null, intent.clOrdID, { reduceOnly: true });
      if (!r.ok) return r;
      return { ok: true, orderID: r.orderID, clOrdID: intent.clOrdID };
    }
    // sltp
    if (!pr.pos) return { ok: false, message: 'No open position to protect' };
    const terr = sltpTriggerOk(intent.kind, pr.pos.side, intent.trigger, pr.pos.mark);
    if (terr) return { ok: false, message: terr };
    const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
    const ordType = intent.kind === 'sl' ? 'stop' : 'tp_market';
    const r = await bnPlace(creds, route, 'futures', pr.pos.symbol, side, ordType,
                            pr.pos.size, null, intent.clOrdID,
                            { reduceOnly: true, trigger: intent.trigger, closePosition: true });
    if (!r.ok) return r;
    return { ok: true, kind: intent.kind, orderID: r.orderID, clOrdID: intent.clOrdID };
  }

  // --- #1943 Binance user-data streams (shell push runtime) -----------------
  // Kraken-grade instant display: per armed slot the shell keeps a spot
  // ws-api signature-subscribe session and a futures /private/ws/<listenKey>
  // session, maintains local-first ledger maps (orders + fills seen-set),
  // bumps a per-scope seq (generic krLseq) on every mutation and pushes
  // coalesced venue-tagged events through the same att:ledger-push fan-out.
  // NO silent fallback: when a socket is down the panel simply keeps riding
  // its existing 5s REST poll (unchanged), and reconnects are surfaced in
  // the diag log. All traffic rides the proxy agent like everything else.
  const bnUdsSessions = {};
  const bnPushPend = {};
  let bnPushTimer = null;
  function bnPushFlush() {
    bnPushTimer = null;
    const evs = krPushDrain(bnPushPend, (key) => {
      const ix = key.indexOf('|');
      const s = bnUdsSessions[key.slice(0, ix)];
      const sc = s && (key.slice(ix + 1) === 'fut' ? s.fut : s.spot);
      return sc ? sc.lseq : 0;
    }, Date.now(), 'binance');
    const tBust = lbT();
    for (const ev of evs) {
      // memo-bust so the push-triggered acct_read observes the mutation
      try { execAcctRead.bust('binance', ev.slot); } catch (e) { /* best-effort */ }
      try { execAcctRead.markHot('binance'); } catch (e) { /* #2131 hot lane */ }
      tdiag('acct', 'bn_push', { s: ev.scope, q: ev.seq, k: ev.kinds.join(',') });
    }
    lbTap('push.bust', tBust);
    // #2212 ONE batched fan-out per drain tick (the drain already folds marks
    // per slot|scope, so this is normally 1-2 events — but a burst that lands
    // spot AND futures mutations in the same tick used to cost one IPC +
    // structured clone per event PER WINDOW). main.js unwraps a 1-event array
    // back to the bare single shape; the panel applies the list in THIS order,
    // so per-event handling (dedup ids, chime ids, blotter kicks) is
    // unchanged. The memo bust above still runs before anything ships.
    if (evs.length) {
      const tB = lbT();
      try { pushLedgerCb(evs); } catch (e) { /* window gone */ }
      lbTap('push.bcast', tB);
    }
  }
  function bnPushSc(scope, kind, id, row) {
    if (!pushLedgerCb || !scope || !scope._pk) return;
    krPushMark(bnPushPend, scope._pk, kind, id, row);
    if (!bnPushTimer) {
      bnPushTimer = setTimeout(bnPushFlush, KR_PUSH_COALESCE_MS);
      if (bnPushTimer && typeof bnPushTimer.unref === 'function') bnPushTimer.unref();
    }
  }
  function bnUdsScope(kind) {
    return { running: false, up: false, ws: null, err: null, lastMsg: 0,
             lseq: 0, orders: {}, fills: { rows: [], seen: {} }, _pk: null };
  }
  function bnUdsClose(slot) {
    const s = bnUdsSessions[slot];
    if (!s) return;
    s.closed = true;
    for (const sc of [s.spot, s.fut]) {
      try { if (sc.ws) sc.ws.terminate(); } catch (e) { /* already gone */ }
      sc.ws = null; sc.up = false;
    }
    delete bnUdsSessions[slot];
  }
  function bnUdsCloseAll() {
    for (const k of Object.keys(bnUdsSessions)) bnUdsClose(k);
  }
  function bnUdsEnsure(slot, creds, route) {
    if (!WSC || !creds || !creds.key || !creds.secret) return null;
    slot = String(slot || 'binance');
    let s = bnUdsSessions[slot];
    if (s && s.tail !== creds.key) { bnUdsClose(slot); s = null; }
    if (!s) {
      s = bnUdsSessions[slot] = {
        tail: creds.key, closed: false, route: route,
        spot: bnUdsScope('spot'), fut: bnUdsScope('fut'),
      };
      s.spot._pk = slot + '|spot';
      s.fut._pk = slot + '|fut';
    }
    s.route = route;   // latest route pick wins for the next (re)dial
    if (!s.spot.running) bnUdsLoop(slot, s, creds, 'spot');
    if (!s.fut.running) bnUdsLoop(slot, s, creds, 'fut');
    return s;
  }
  function bnUdsLoop(slot, s, creds, which) {
    const S = which === 'fut' ? s.fut : s.spot;
    S.running = true;
    (async () => {
      let backoff = 2000;
      while (bnUdsSessions[slot] === s && !s.closed) {
        const t0 = Date.now();
        try {
          if (which === 'fut') await bnUdsFutConn(slot, s, creds);
          else await bnUdsSpotConn(slot, s, creds);
          if (Date.now() - t0 > 60000) backoff = 2000;   // productive conn resets
        } catch (e) {
          S.err = 'Binance ' + which + ' stream: ' + ((e && e.message) || 'error');
          tdiag('acct', 'bn_uds_err', { w: which, m: String(S.err).slice(0, 120) });
          // #2192: a timestamp-rejection on the signed ws-api subscribe =
          // poisoned clock offset — invalidate so the redial re-probes
          // instead of re-signing 1000ms ahead for the whole session.
          if (clkTsReject(null, e && e.message)) {
            clkInvalidate('binance', which === 'fut' ? 'futures' : 'spot');
          }
        }
        S.up = false; S.ws = null;
        if (s.closed || bnUdsSessions[slot] !== s) break;
        await krWsSleep(backoff);
        backoff = Math.min(backoff * 2, 60000);
      }
      S.running = false;
    })().catch(() => { S.running = false; });
  }
  function bnUdsSpotConn(slot, s, creds) {
    return new Promise((resolve, reject) => {
      const ws = krWsDial(BN_SPOT_WSAPI_URL, s.route);
      if (!ws) { reject(new Error('proxy agent unavailable')); return; }
      const S = s.spot;
      S.ws = ws;
      let settled = false;
      const done = (err) => {
        if (settled) return;
        settled = true;
        S.up = false;
        try { ws.terminate(); } catch (e) { /* closed */ }
        if (err) reject(err); else resolve();
      };
      ws.on('open', async () => {
        try {
          // fresh signed subscribe frame each (re)connect — venue clock,
          // never raw Date.now() (-1021 discipline)
          const offMs = await ensureVenueTime('binance', 'spot', s.route);
          ws.send(JSON.stringify(bnSpotSubscribeFrame(
            creds.key, creds.secret, Number(venueStampMs(offMs)))));
        } catch (e) { done(e); }
      });
      ws.on('ping', () => { S.lastMsg = Date.now(); });
      ws.on('message', (buf) => {
        S.lastMsg = Date.now();
        let msg = null;
        try { msg = JSON.parse(buf.toString()); } catch (e) { return; }
        if (msg && msg.id != null && msg.status != null) {
          // subscribe ack — status!=200 is a hard, visible failure
          if (Number(msg.status) === 200) {
            S.up = true; S.err = null;
            tdiag('acct', 'bn_uds_up', { w: 'spot' });
          } else {
            done(new Error('spot subscribe failed: ' +
              String(((msg.error || {}).msg) || msg.status).slice(0, 120)));
          }
          return;
        }
        const ev = bnWsEvent(msg);
        if (!ev) return;
        try { bnSpotEvApply(S, ev, done); } catch (e) { /* row skipped */ }
      });
      ws.on('error', (e) => done(e || new Error('ws error')));
      ws.on('close', () => done(new Error('closed')));
    });
  }
  function bnSpotEvApply(B, ev, done) {
    const t = String(ev.e || '');
    if (t === 'eventStreamTerminated') { done(new Error('stream terminated')); return; }
    if (t === 'outboundAccountPosition' || t === 'balanceUpdate') {
      // #1945: outboundAccountPosition carries the changed wallet rows (B:
      // [{a,f,l}]) — ship them so spot wallets/posrow step on the push beat.
      // balanceUpdate ({a,d} delta) stays kind-only (no absolute row).
      const bs = Array.isArray(ev.B) ? ev.B : [];
      krLseq(B);
      if (bs.length) { for (const b of bs) bnPushSc(B, 'bal', null, b); }
      else bnPushSc(B, 'bal');
      return;
    }
    if (t !== 'executionReport') return;
    if (String(ev.x) === 'TRADE' && Number(ev.l) > 0) {
      const fid = bnFillIngest(B.fills, 's', ev.t);
      if (fid) {
        // #1950: the RAW executionReport rides the push (bnPushSc row →
        // frows) — commission (n) + commissionAsset (N) included, so the
        // panel's fee-inclusive cost-basis replay and the pending blotter
        // row carry the fee the same beat. Never slim this row.
        const row = Object.assign({ _fid: fid }, ev);
        B.fills.rows.push(row);
        if (B.fills.rows.length > BN_UDS_FILLS_CAP) {
          B.fills.rows.splice(0, B.fills.rows.length - BN_UDS_FILLS_CAP);
        }
        lbSrcTouch(B.fills);   // #2230
        krLseq(B); bnPushSc(B, 'fill', fid, ev);
      }
    }
    const oid = String(ev.i != null ? ev.i : '');
    const eff = bnOrdEffect(ev.X);
    if (!oid || !eff) return;
    if (eff === 'add') {
      B.orders[oid] = ev;
      krLseq(B); bnPushSc(B, 'order', null, ev);
    } else {
      if (B.orders[oid]) delete B.orders[oid];
      krLseq(B); bnPushSc(B, 'ordgone', oid);
    }
  }
  async function bnListenKey(creds, route, method) {
    // API-key header only — unsigned by design (Binance listenKey REST)
    let r;
    try {
      r = await httpJson(BINANCE_FUT_HOST, method || 'POST', '/fapi/v1/listenKey',
                         '', null, { 'X-MBX-APIKEY': creds.key }, route);
    } catch (e) { return { ok: false, message: (e && e.message) || 'transport error' }; }
    // #2026: 418/429 armed the freeze latch in httpJson — surface the honest
    // ban message instead of a raw HTTP status line.
    if (r.status === 418 || r.status === 429) {
      const bst = _bnBanReg[BINANCE_FUT_HOST];
      if (bst && bst.until > Date.now()) return { ok: false, message: bnBanMsgFor(bst) };
    }
    let data = null;
    try { data = JSON.parse(r.text); } catch (e) { /* PUT returns {} */ }
    if (r.status >= 400) {
      return { ok: false, message: 'HTTP ' + r.status + ' ' +
               String((data && data.msg) || '').slice(0, 100) };
    }
    return { ok: true, key: String((data && data.listenKey) || '') };
  }
  async function bnUdsFutConn(slot, s, creds) {
    const lk = await bnListenKey(creds, s.route, 'POST');
    if (!lk.ok || !lk.key) throw new Error('listenKey: ' + (lk.message || 'empty'));
    return new Promise((resolve, reject) => {
      // routed /private/ws path — the plain /ws/<lk> connects but pushes
      // nothing (same fact the server engine path learned 2026-04-23)
      const ws = krWsDial(BN_FUT_WS_BASE + lk.key, s.route);
      if (!ws) { reject(new Error('proxy agent unavailable')); return; }
      const F = s.fut;
      F.ws = ws;
      let settled = false;
      // keepalive PUT every 30 min (60 min expiry) — a failed keepalive
      // tears the conn down for a clean redial with a fresh key; interval
      // pacing keeps REST churn at 2 calls/hour (rate-limit friendly).
      const kaT = setInterval(async () => {
        try {
          const ka = await bnListenKey(creds, s.route, 'PUT');
          if (!ka.ok) done(new Error('listenKey keepalive: ' + (ka.message || 'failed')));
        } catch (e) { /* transient — next tick retries */ }
      }, BN_LK_KEEPALIVE_MS);
      if (kaT && typeof kaT.unref === 'function') kaT.unref();
      const done = (err) => {
        if (settled) return;
        settled = true;
        clearInterval(kaT);
        F.up = false;
        try { ws.terminate(); } catch (e) { /* closed */ }
        if (err) reject(err); else resolve();
      };
      ws.on('open', () => {
        F.up = true; F.err = null; F.lastMsg = Date.now();
        tdiag('acct', 'bn_uds_up', { w: 'fut' });
      });
      ws.on('ping', () => { F.lastMsg = Date.now(); });
      ws.on('message', (buf) => {
        F.lastMsg = Date.now();
        let msg = null;
        try { msg = JSON.parse(buf.toString()); } catch (e) { return; }
        const ev = bnWsEvent(msg);
        if (!ev) return;
        try { bnFutEvApply(F, ev, done); } catch (e) { /* row skipped */ }
      });
      ws.on('error', (e) => done(e || new Error('ws error')));
      ws.on('close', () => done(new Error('closed')));
    });
  }
  function bnFutEvApply(B, ev, done) {
    const t = String(ev.e || '');
    if (t === 'listenKeyExpired') { done(new Error('listenKey expired')); return; }
    if (t === 'ACCOUNT_UPDATE') {
      // #1945: ship the actual mutated rows (a.P positions / a.B balances)
      // so the panel's posrow steps on the push beat — a kind-only flag can
      // only mark-dirty and wait out the paced REST re-read (1-1.5s).
      const a = ev.a || {};
      const ps = Array.isArray(a.P) ? a.P : [];
      const bs = Array.isArray(a.B) ? a.B : [];
      krLseq(B);
      if (ps.length) { for (const p of ps) bnPushSc(B, 'pos', null, p); }
      else bnPushSc(B, 'pos');
      krLseq(B);
      if (bs.length) { for (const b of bs) bnPushSc(B, 'bal', null, b); }
      else bnPushSc(B, 'bal');
      return;
    }
    if (t !== 'ORDER_TRADE_UPDATE') return;
    const o = ev.o || {};
    if (String(o.x) === 'TRADE' && Number(o.l) > 0) {
      const fid = bnFillIngest(B.fills, 'f', o.t);
      if (fid) {
        // stamp the event ts on the o payload (engine normalizer fallback).
        // #1950: the RAW OTU `o` payload rides the push — commission (n) +
        // commissionAsset (N) included (fee passthrough). Never slim it.
        const row = Object.assign({ _fid: fid }, o);
        if (row.T == null && ev.T != null) row.T = ev.T;
        B.fills.rows.push(row);
        if (B.fills.rows.length > BN_UDS_FILLS_CAP) {
          B.fills.rows.splice(0, B.fills.rows.length - BN_UDS_FILLS_CAP);
        }
        lbSrcTouch(B.fills);   // #2230
        krLseq(B); bnPushSc(B, 'fill', fid, row);
      }
      krLseq(B); bnPushSc(B, 'pos');   // a fill moves the position — refresh
    }
    const oid = String(o.i != null ? o.i : '');
    const eff = bnOrdEffect(o.X);
    if (!oid || !eff) return;
    if (eff === 'add') {
      B.orders[oid] = o;
      krLseq(B); bnPushSc(B, 'order', null, o);
    } else {
      if (B.orders[oid]) delete B.orders[oid];
      krLseq(B); bnPushSc(B, 'ordgone', oid);
    }
  }
  // --- #2000 Hyperliquid account push lane -----------------------------------
  // HL's public info WS is ADDRESS-keyed (no signing): userFills + orderUpdates
  // subscribed for the armed account's MASTER address give a Kraken-style push
  // channel. Agent creds resolve agent→master via a userRole probe (the creds
  // key can BE an agent address); probe failure retries on the next redial.
  // ONE 'acct' scope per slot — HL account events are account-level, so spot,
  // perp AND HIP-3 builder dexes all ride the same two subscriptions.
  // Snapshot frames seed the seen-set only (dedup), never push. All traffic
  // rides the proxy agent like everything else.
  const HL_WS_URL = 'wss://' + HL_HOST + '/ws';
  const HL_PUSH_FILLS_CAP = 600;
  const hlPushSessions = {};
  const hlPushPend = {};
  let hlPushTimer = null;
  function hlPushFlush() {
    hlPushTimer = null;
    const evs = krPushDrain(hlPushPend, (key) => {
      const sess = hlPushSessions[key.slice(0, key.indexOf('|'))];
      return sess ? sess.acct.lseq : 0;
    }, Date.now(), 'hyperliquid');
    for (const ev of evs) {
      try { pushLedgerCb(ev); } catch (e) { /* window gone */ }
      try { execAcctRead.markHot('hyperliquid'); } catch (e) { /* #2131 hot lane */ }
      tdiag('acct', 'hl_push', { s: ev.scope, q: ev.seq, k: ev.kinds.join(',') });
    }
    // #2020 push-beat local-blotter drain: fills land in the local store on
    // the push flush itself (idempotent — lbDrain dedups by exec_id), so the
    // panel's push-kicked read serves already-drained rows and the store
    // stays current even with every window hidden. Fill events only.
    try {
      for (const ev of evs) {
        if (ev && ev.kinds && ev.kinds.indexOf('fill') >= 0)
          lbDrain(String(ev.slot || 'hyperliquid'), 'hyperliquid');
      }
    } catch (e) { /* local store off — panel read drains later */ }
  }
  function hlPushSc(scope, kind, id, row) {
    if (!pushLedgerCb || !scope || !scope._pk) return;
    krPushMark(hlPushPend, scope._pk, kind, id, row);
    if (!hlPushTimer) {
      hlPushTimer = setTimeout(hlPushFlush, KR_PUSH_COALESCE_MS);
      if (hlPushTimer && typeof hlPushTimer.unref === 'function') hlPushTimer.unref();
    }
  }
  function hlPushClose(slot) {
    const sess = hlPushSessions[slot];
    if (!sess) return;
    sess.closed = true;
    try { if (sess.acct.ws) sess.acct.ws.terminate(); } catch (e) { /* gone */ }
    sess.acct.ws = null; sess.acct.up = false;
    delete hlPushSessions[slot];
  }
  function hlPushCloseAll() {
    for (const k of Object.keys(hlPushSessions)) hlPushClose(k);
  }
  async function hlMasterResolve(addr, route) {
    // agent→master: subscribing for an AGENT address gets NO account events —
    // the probe is mandatory before the first subscribe (hl-agent-master rule).
    const r = await hlInfo({ type: 'userRole', user: addr }, route);
    if (!r.ok || !r.data) throw new Error('userRole probe: ' + (r.message || 'empty'));
    if (String(r.data.role || '') === 'agent') {
      const m = String(((r.data || {}).data || {}).user || '');
      if (!/^0x[0-9a-fA-F]{40}$/.test(m)) throw new Error('agent master address missing');
      return m;
    }
    return addr;
  }
  function hlPushEnsure(slot, creds, route) {
    if (!WSC || !creds || !creds.key) return null;
    slot = String(slot || 'hyperliquid');
    let sess = hlPushSessions[slot];
    if (sess && sess.tail !== creds.key) { hlPushClose(slot); sess = null; }
    if (!sess) {
      sess = hlPushSessions[slot] = {
        tail: creds.key, closed: false, route: route,
        acct: { running: false, up: false, ws: null, err: null, lastMsg: 0,
                lseq: 0, user: null, fills: { rows: [], seen: {} }, _pk: null },
      };
      sess.acct._pk = slot + '|acct';
    }
    sess.route = route;   // latest route pick wins for the next (re)dial
    if (!sess.acct.running) hlPushLoop(slot, sess, creds);
    return sess;
  }
  function hlPushLoop(slot, sess, creds) {
    const A = sess.acct;
    A.running = true;
    (async () => {
      let backoff = 2000;
      while (hlPushSessions[slot] === sess && !sess.closed) {
        const t0 = Date.now();
        try {
          // A.user is a READ/SUBSCRIBE address only (userFills/orderUpdates
          // are account-level, keyed by the MASTER). Signing identity is
          // never touched here: hlSignAction derives the signer from the
          // PRIVATE KEY alone (creds.secret) — an agent key keeps signing
          // as the agent wallet regardless of what creds.key resolves to.
          if (!A.user) A.user = await hlMasterResolve(String(creds.key).trim(), sess.route);
          await hlPushConn(slot, sess);
          if (Date.now() - t0 > 60000) backoff = 2000;   // productive conn resets
        } catch (e) {
          A.err = 'Hyperliquid push: ' + ((e && e.message) || 'error');
          tdiag('acct', 'hl_push_err', { m: String(A.err).slice(0, 120) });
        }
        A.up = false; A.ws = null;
        if (sess.closed || hlPushSessions[slot] !== sess) break;
        await krWsSleep(backoff);
        backoff = Math.min(backoff * 2, 60000);
      }
      A.running = false;
    })().catch(() => { A.running = false; });
  }
  function hlPushConn(slot, sess) {
    return new Promise((resolve, reject) => {
      const ws = krWsDial(HL_WS_URL, sess.route);
      if (!ws) { reject(new Error('proxy agent unavailable')); return; }
      const A = sess.acct;
      A.ws = ws;
      let settled = false;
      const done = (err) => {
        if (settled) return;
        settled = true;
        clearInterval(kaT);
        A.up = false;
        try { ws.terminate(); } catch (e) { /* closed */ }
        if (err) reject(err); else resolve();
      };
      // HL idle-closes quiet conns — app-level {method:'ping'} every 30s
      // keeps it live; a 90s frame gap tears down for a clean redial.
      const kaT = setInterval(() => {
        try { ws.send('{"method":"ping"}'); } catch (e) { /* dying */ }
        if (Date.now() - (A.lastMsg || 0) > 90000) done(new Error('stream stalled'));
      }, 30000);
      if (kaT && typeof kaT.unref === 'function') kaT.unref();
      ws.on('open', () => {
        A.lastMsg = Date.now();
        try {
          ws.send(JSON.stringify({ method: 'subscribe',
            subscription: { type: 'userFills', user: A.user } }));
          ws.send(JSON.stringify({ method: 'subscribe',
            subscription: { type: 'orderUpdates', user: A.user } }));
        } catch (e) { done(e); return; }
        A.up = true; A.err = null;
        tdiag('acct', 'hl_push_up', { u: String(A.user).slice(0, 8) });
      });
      ws.on('ping', () => { A.lastMsg = Date.now(); });
      ws.on('message', (buf) => {
        A.lastMsg = Date.now();
        let msg = null;
        try { msg = JSON.parse(buf.toString()); } catch (e) { return; }
        try { hlPushEvApply(A, msg); } catch (e) { /* row skipped */ }
      });
      ws.on('error', (e) => done(e || new Error('ws error')));
      ws.on('close', () => done(new Error('closed')));
    });
  }
  function hlPushEvApply(A, msg) {
    const ch = String((msg && msg.channel) || '');
    if (ch === 'userFills') {
      const d = (msg && msg.data) || {};
      const fills = Array.isArray(d.fills) ? d.fills : [];
      const snap = !!d.isSnapshot;
      for (const f of fills) {
        const tid = f && f.tid != null ? String(f.tid) : '';
        if (!tid || A.fills.seen[tid]) continue;
        A.fills.seen[tid] = 1;
        if (snap) continue;   // snapshot seeds dedup ONLY — never pushes
        // RAW fill row rides the push (coin/px/sz/side/time/fee/feeToken/
        // closedPnl/dir all included — fee passthrough). Never slim it.
        A.fills.rows.push(f);
        if (A.fills.rows.length > HL_PUSH_FILLS_CAP) {
          A.fills.rows.splice(0, A.fills.rows.length - HL_PUSH_FILLS_CAP);
        }
        lbSrcTouch(A.fills);   // #2230
        krLseq(A); hlPushSc(A, 'fill', tid, f);
        krLseq(A); hlPushSc(A, 'pos');   // a fill moves the position — refresh
      }
      return;
    }
    if (ch !== 'orderUpdates') return;
    const rows = Array.isArray(msg && msg.data) ? msg.data : [];
    for (const u of rows) {
      const o = (u || {}).order || {};
      const oid = o.oid != null ? String(o.oid) : '';
      if (!oid) continue;
      const st = String((u || {}).status || '');
      if (st === 'open') {
        // flattened row (order fields + status) — the panel's tolerant
        // hlAcctOrderRow reads the WS basic-order shape directly.
        const row = Object.assign({}, o, { status: st,
          statusTimestamp: (u || {}).statusTimestamp });
        krLseq(A); hlPushSc(A, 'order', null, row);
      } else {
        krLseq(A); hlPushSc(A, 'ordgone', oid);
      }
    }
  }

  // Optimistic mutation stamps at the order-send/cancel sites (Kraken
  // pattern): the WS echo lands ~100ms later, but the local bump makes the
  // badge/posrow read fire immediately after the REST ack.
  function bnMutKick(slot, market, kind, oid) {
    const s = bnUdsSessions[String(slot || 'binance')];
    if (!s) return;
    const B = market === 'futures' ? s.fut : s.spot;
    if (kind === 'ordgone' && oid) {
      if (B.orders[oid]) delete B.orders[oid];
      krLseq(B); bnPushSc(B, 'ordgone', String(oid));
    } else {
      krLseq(B); bnPushSc(B, 'order');
    }
  }

  // --- #2051 Bybit account push lane -------------------------------------------
  // Bybit V5 private WS (wss://stream.bybit.com/v5/private): auth per V5
  // (HMAC over 'GET/realtime<expires>'), then order/execution/position/wallet
  // topics. Topics have NO snapshot frame — a best-effort REST seed marks
  // recent exec ids in the seen-set (dedup ONLY, push is truth). ONE 'acct'
  // scope per slot: V5 topics are account-level (rows carry `category`), so
  // linear AND spot ride the same socket. Rides the proxy agent like all
  // shell traffic; reconnect via the shared backoff ladder.
  const BYB_PUSH_WS_URL = 'wss://stream.bybit.com/v5/private';
  const BYB_PUSH_FILLS_CAP = 600;
  const bybPushSessions = {};
  const bybPushPend = {};
  let bybPushTimer = null;
  function bybPushFlush() {
    bybPushTimer = null;
    const evs = krPushDrain(bybPushPend, (key) => {
      const sess = bybPushSessions[key.slice(0, key.indexOf('|'))];
      return sess ? sess.acct.lseq : 0;
    }, Date.now(), 'bybit');
    for (const ev of evs) {
      try { pushLedgerCb(ev); } catch (e) { /* window gone */ }
      // a mutation observed on the push beat invalidates the acct-read memo
      // (Binance flush pattern) so the push-kicked read never serves stale.
      try { execAcctRead.bust('bybit', ev.slot); } catch (e) { /* no memo */ }
      try { execAcctRead.markHot('bybit'); } catch (e) { /* #2131 hot lane */ }
      tdiag('acct', 'byb_push', { s: ev.scope, q: ev.seq, k: ev.kinds.join(',') });
    }
    // push-beat local-blotter drain (HL pattern): fills land in the local
    // store on the flush itself (idempotent — lbDrain dedups by exec_id).
    try {
      for (const ev of evs) {
        if (ev && ev.kinds && ev.kinds.indexOf('fill') >= 0)
          lbDrain(String(ev.slot || 'bybit'), 'bybit');
      }
    } catch (e) { /* local store off — panel read drains later */ }
  }
  function bybPushSc(scope, kind, id, row) {
    if (!pushLedgerCb || !scope || !scope._pk) return;
    krPushMark(bybPushPend, scope._pk, kind, id, row);
    if (!bybPushTimer) {
      bybPushTimer = setTimeout(bybPushFlush, KR_PUSH_COALESCE_MS);
      if (bybPushTimer && typeof bybPushTimer.unref === 'function') bybPushTimer.unref();
    }
  }
  function bybPushClose(slot) {
    const sess = bybPushSessions[slot];
    if (!sess) return;
    sess.closed = true;
    try { if (sess.acct.ws) sess.acct.ws.terminate(); } catch (e) { /* gone */ }
    sess.acct.ws = null; sess.acct.up = false;
    delete bybPushSessions[slot];
  }
  function bybPushCloseAll() {
    for (const k of Object.keys(bybPushSessions)) bybPushClose(k);
  }
  function bybPushEnsure(slot, creds, route) {
    if (!WSC || !creds || !creds.key) return null;
    slot = String(slot || 'bybit');
    let sess = bybPushSessions[slot];
    if (sess && sess.tail !== creds.key) { bybPushClose(slot); sess = null; }
    if (!sess) {
      sess = bybPushSessions[slot] = {
        tail: creds.key, closed: false, route: route, creds: creds,
        acct: { running: false, up: false, ws: null, err: null, lastMsg: 0,
                lseq: 0, seeded: false, fills: { rows: [], seen: {} }, _pk: null },
      };
      sess.acct._pk = slot + '|acct';
    }
    sess.route = route;   // latest route pick wins for the next (re)dial
    sess.creds = creds;
    if (!sess.acct.running) bybPushLoop(slot, sess);
    return sess;
  }
  async function bybPushSeed(sess) {
    // dedup-only seed: the private topics have no snapshot frame, so recent
    // REST exec ids pre-mark the seen-set (a fill recorded by the poll path
    // milliseconds before the socket came up must not re-push). Best-effort:
    // a failed seed only risks one duplicate push, which lbScopeMerge and the
    // panel eid dedupe both absorb.
    const A = sess.acct;
    if (A.seeded) return;
    A.seeded = true;
    for (const cat of ['linear', 'spot']) {
      try {
        const r = await bybRequest(sess.creds, 'GET', '/v5/execution/list',
          [['category', cat], ['limit', '50']], null, sess.route);
        if (!r.ok) continue;
        for (const f of (((r.data || {}).result) || {}).list || []) {
          const eid = f && f.execId != null ? String(f.execId) : '';
          if (eid) A.fills.seen[eid] = 1;
        }
      } catch (e) { /* best-effort */ }
    }
  }
  function bybPushLoop(slot, sess) {
    const A = sess.acct;
    A.running = true;
    (async () => {
      let backoff = 2000;
      while (bybPushSessions[slot] === sess && !sess.closed) {
        const t0 = Date.now();
        try {
          await bybPushSeed(sess);
          await bybPushConn(slot, sess);
          if (Date.now() - t0 > 60000) backoff = 2000;   // productive conn resets
        } catch (e) {
          A.err = 'Bybit push: ' + ((e && e.message) || 'error');
          tdiag('acct', 'byb_push_err', { m: String(A.err).slice(0, 120) });
        }
        A.up = false; A.ws = null;
        if (sess.closed || bybPushSessions[slot] !== sess) break;
        await krWsSleep(backoff);
        backoff = Math.min(backoff * 2, 60000);
      }
      A.running = false;
    })().catch(() => { A.running = false; });
  }
  function bybPushConn(slot, sess) {
    return new Promise((resolve, reject) => {
      const ws = krWsDial(BYB_PUSH_WS_URL, sess.route);
      if (!ws) { reject(new Error('proxy agent unavailable')); return; }
      const A = sess.acct;
      A.ws = ws;
      let settled = false;
      const done = (err) => {
        if (settled) return;
        settled = true;
        clearInterval(kaT);
        A.up = false;
        try { ws.terminate(); } catch (e) { /* closed */ }
        if (err) reject(err); else resolve();
      };
      // Bybit idle-closes quiet conns — app-level {op:'ping'} every 20s keeps
      // it live; a 90s frame gap tears down for a clean redial.
      const kaT = setInterval(() => {
        try { ws.send('{"op":"ping"}'); } catch (e) { /* dying */ }
        if (Date.now() - (A.lastMsg || 0) > 90000) done(new Error('stream stalled'));
      }, 20000);
      if (kaT && typeof kaT.unref === 'function') kaT.unref();
      ws.on('open', () => {
        A.lastMsg = Date.now();
        try {
          const expires = Date.now() + 10000;
          ws.send(JSON.stringify({ op: 'auth', args: [
            sess.creds.key, expires, bybWsAuthSig(sess.creds.secret, expires)] }));
        } catch (e) { done(e); return; }
      });
      ws.on('ping', () => { A.lastMsg = Date.now(); });
      ws.on('message', (buf) => {
        A.lastMsg = Date.now();
        let msg = null;
        try { msg = JSON.parse(buf.toString()); } catch (e) { return; }
        const op = String((msg && msg.op) || '');
        if (op === 'auth') {
          if (msg.success === false) { done(new Error('auth rejected: ' + String(msg.ret_msg || ''))); return; }
          try {
            ws.send(JSON.stringify({ op: 'subscribe',
              args: ['position', 'order', 'execution', 'wallet'] }));
          } catch (e) { done(e); return; }
          return;
        }
        if (op === 'subscribe') {
          if (msg.success === false) { done(new Error('subscribe rejected: ' + String(msg.ret_msg || ''))); return; }
          A.up = true; A.err = null;
          tdiag('acct', 'byb_push_up', { s: slot });
          return;
        }
        if (op === 'pong' || op === 'ping') return;
        try { bybPushEvApply(A, msg); } catch (e) { /* row skipped */ }
      });
      ws.on('error', (e) => done(e || new Error('ws error')));
      ws.on('close', () => done(new Error('closed')));
    });
  }
  function bybPushEvApply(A, msg) {
    const topic = String((msg && msg.topic) || '');
    const rows = Array.isArray(msg && msg.data) ? msg.data : [];
    if (!topic || !rows.length) return;
    if (topic === 'execution') {
      for (const f of rows) {
        if (String((f && f.execType) || 'Trade') !== 'Trade') continue;
        const eid = f && f.execId != null ? String(f.execId) : '';
        if (!eid || A.fills.seen[eid]) continue;
        A.fills.seen[eid] = 1;
        // RAW execution row rides the push (category/symbol/side/execPrice/
        // execQty/execFee/feeCurrency/execPnl/execTime all included — fee
        // passthrough). Never slim it.
        A.fills.rows.push(f);
        if (A.fills.rows.length > BYB_PUSH_FILLS_CAP) {
          A.fills.rows.splice(0, A.fills.rows.length - BYB_PUSH_FILLS_CAP);
        }
        lbSrcTouch(A.fills);   // #2230
        krLseq(A); bybPushSc(A, 'fill', eid, f);
        krLseq(A); bybPushSc(A, 'pos');   // a fill moves the position — refresh
      }
      return;
    }
    if (topic === 'order') {
      for (const o of rows) {
        const oid = o && o.orderId != null ? String(o.orderId) : '';
        if (!oid) continue;
        const eff = bybOrdEffect(o.orderStatus);
        if (eff === 'add') {
          // WS order rows are REST /v5/order/realtime-shaped — the panel's
          // bybAcctOrderRow reads them directly (category routes market).
          krLseq(A); bybPushSc(A, 'order', null, o);
        } else if (eff === 'gone') {
          krLseq(A); bybPushSc(A, 'ordgone', oid);
        }
      }
      return;
    }
    if (topic === 'position') {
      for (const p of rows) { krLseq(A); bybPushSc(A, 'pos', null, p); }
      return;
    }
    if (topic === 'wallet') {
      // #2072: stamp the wallet FRAME's venue ts (creationTime — falls back
      // to the envelope ts) onto every shipped coin row. The panel's overlay
      // consume/skip-arm orders fills vs wallet frames by VENUE truth (exec
      // execTime vs frame crTs) instead of local arrival clocks — the
      // same-beat/out-of-order frame race double-counted the spot posrow.
      // Additive field; bybWalletUpsert/older panels ignore it.
      const wTs = Number((msg && msg.creationTime) || (msg && msg.ts)) || 0;
      for (const w of rows) {
        let wr = w;
        if (wTs > 0 && w && typeof w === 'object') {
          const cs = Array.isArray(w.coin)
            ? w.coin.map((c) => (c && typeof c === 'object')
                ? Object.assign({}, c, { crTs: wTs }) : c)
            : w.coin;
          wr = Object.assign({}, w, { coin: cs });
        }
        krLseq(A); bybPushSc(A, 'bal', null, wr);
      }
    }
  }
  // Optimistic mutation stamp at the order-send/cancel ack sites (Kraken/
  // Binance pattern): the WS echo lands ~100ms later, but the local bump
  // makes the badge/posrow read fire immediately after the REST ack.
  function bybMutKick(slot, kind, oid) {
    const sess = bybPushSessions[String(slot || 'bybit')];
    if (!sess) return;
    const A = sess.acct;
    if (kind === 'ordgone' && oid) {
      krLseq(A); bybPushSc(A, 'ordgone', String(oid));
    } else {
      krLseq(A); bybPushSc(A, 'order');
    }
  }

  // --- Bybit -------------------------------------------------------------------
  async function bybRequest(creds, method, reqPath, params, body, route) {
    const ts = venueStampMs(await ensureVenueTime('bybit', null, route));
    const q = params && params.length ? formEnc(params) : '';
    const bodyStr = body != null ? canonJson(body) : '';
    const payload = method === 'GET' ? q : bodyStr;
    const headers = {
      'X-BAPI-API-KEY': creds.key,
      'X-BAPI-TIMESTAMP': ts,
      'X-BAPI-RECV-WINDOW': String(BYBIT_RECV_WINDOW_MS),
      'X-BAPI-SIGN': bybitSign(creds.secret, ts, creds.key, String(BYBIT_RECV_WINDOW_MS), payload),
    };
    let r;
    try {
      r = await httpJson(BYBIT_HOST, method, reqPath, q, bodyStr || null, headers, route);
    } catch (e) { return transportFail(e, 'Bybit'); }
    if (r.status === 429) return { ok: false, message: 'Rate limited by Bybit — retry shortly' };
    let data;
    try { data = JSON.parse(r.text); } catch (e) {
      return { ok: false, message: 'Bybit returned HTTP ' + r.status };
    }
    const rc = Number(data && data.retCode);
    if (rc !== 0) {
      return { ok: false, message: bybitErrorMessage(rc, String((data && data.retMsg) || '')), code: rc };
    }
    return { ok: true, data: data };
  }

  async function bybMarkPrice(symbol, route) {
    // Unsigned tickers read for the conditional triggerDirection inference.
    try {
      const r = await httpJson(BYBIT_HOST, 'GET', '/v5/market/tickers',
                               formEnc([['category', 'linear'], ['symbol', symbol]]),
                               null, {}, route);
      const d = JSON.parse(r.text);
      const lst = (((d || {}).result) || {}).list || [];
      for (const t of lst) {
        const v = bnNum(t.markPrice) || bnNum(t.lastPrice);
        if (v) return v;
      }
    } catch (e) { /* null */ }
    return null;
  }

  async function execBybit(creds, intent, route) {
    const market = intent.market === 'spot' ? 'spot' : 'futures';
    const fetchPos = async () => {
      const all = [];
      let cursor = '';
      for (let page = 0; page < 10; page++) {
        const params = [['category', 'linear'], ['settleCoin', 'USDT'], ['limit', '200']];
        if (cursor) params.push(['cursor', cursor]);
        const r = await bybRequest(creds, 'GET', '/v5/position/list', params, null, route);
        if (!r.ok) return r;
        const res = ((r.data || {}).result) || {};
        for (const p of res.list || []) all.push(p);
        cursor = String(res.nextPageCursor || '');
        if (!cursor) break;
      }
      return { ok: true, rows: bybPositionRows({ result: { list: all } }) };
    };
    async function place(mkt, symbol, side, ordType, qty, price, clOrdID, flags) {
      const f = flags || {};
      const t = String(ordType).toLowerCase();
      const isStop = t === 'stop' || t === 'stop_limit' || t === 'tp_market';
      if (f.closeOnTrigger && mkt === 'futures' && isStop) {
        // Bybit-native SL/TP bracket: /v5/position/trading-stop, tpslMode
        // Full — whole position, reduce-only by construction, vs MARK.
        const body = { category: 'linear', symbol: String(symbol),
                       positionIdx: 0, tpslMode: 'Full' };
        if (t === 'tp_market') {
          body.takeProfit = String(f.trigger);
          body.tpTriggerBy = 'MarkPrice';
        } else {
          body.stopLoss = String(f.trigger);
          body.slTriggerBy = 'MarkPrice';
        }
        const r = await bybRequest(creds, 'POST', '/v5/position/trading-stop', null, body, route);
        if (!r.ok) return r;
        return { ok: true, orderID: null, clOrdID: clOrdID };
      }
      let trigDir = null;
      if (isStop && mkt === 'futures') {
        const ref = await bybMarkPrice(symbol, route);
        if (ref != null && isFinite(Number(ref)) && isFinite(Number(f.trigger))) {
          trigDir = Number(f.trigger) > Number(ref) ? 1 : 2;
        }
        if (trigDir == null) {
          return { ok: false, message: 'Could not read the current price to place the stop — try again' };
        }
      }
      const body = bybitOrderBody(mkt, symbol, side, ordType, qty, price, clOrdID,
                                  { reduceOnly: !!f.reduceOnly,
                                    trigger: isStop ? f.trigger : null,
                                    triggerDirection: trigDir });
      const r = await bybRequest(creds, 'POST', '/v5/order/create', null, body, route);
      if (!r.ok) return r;
      const res = ((r.data || {}).result) || {};
      return { ok: true, orderID: String(res.orderId || '') || null, clOrdID: clOrdID };
    }
    if (intent.op === 'order') {
      return place(market, intent.symbol, intent.side, intent.type,
                   intent.qty, intent.price, intent.clOrdID,
                   { reduceOnly: !!intent.reduceOnly, trigger: intent.trigger });
    }
    if (intent.op === 'cancel') {
      const body = { category: market === 'futures' ? 'linear' : 'spot',
                     symbol: String(intent.symbol), orderId: String(intent.orderID) };
      const r = await bybRequest(creds, 'POST', '/v5/order/cancel', null, body, route);
      if (!r.ok) return r;
      return { ok: true, cancelled: intent.orderID };
    }
    if (intent.op === 'cancel_all') {
      // ONE bulk call per market: linear cancel-all sweeps limits AND stops.
      const body = { category: market === 'futures' ? 'linear' : 'spot',
                     symbol: String(intent.symbol) };
      const r = await bybRequest(creds, 'POST', '/v5/order/cancel-all', null, body, route);
      if (!r.ok) return r;
      return { ok: true, cancelled: 'all' };
    }
    const pr = await findPosRetry(fetchPos, intent.symbol);
    if (!pr.ok) return pr;
    if (intent.op === 'close') {
      if (!pr.pos) return { ok: false, message: 'Position not found' };
      const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
      const r = await place('futures', pr.pos.symbol, side, 'market', pr.pos.size,
                            null, intent.clOrdID, { reduceOnly: true });
      if (!r.ok) return r;
      return { ok: true, orderID: r.orderID, clOrdID: intent.clOrdID };
    }
    if (!pr.pos) return { ok: false, message: 'No open position to protect' };
    const terr = sltpTriggerOk(intent.kind, pr.pos.side, intent.trigger, pr.pos.mark);
    if (terr) return { ok: false, message: terr };
    const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
    const ordType = intent.kind === 'sl' ? 'stop' : 'tp_market';
    const r = await place('futures', pr.pos.symbol, side, ordType, pr.pos.size,
                          null, intent.clOrdID,
                          { reduceOnly: true, trigger: intent.trigger, closeOnTrigger: true });
    if (!r.ok) return r;
    return { ok: true, kind: intent.kind, orderID: r.orderID, clOrdID: intent.clOrdID };
  }

  // --- OKX ---------------------------------------------------------------------
  async function okxRequest(creds, method, reqPath, params, body, route) {
    const q = params && params.length ? formEnc(params) : '';
    const bodyStr = body != null ? canonJson(body) : '';
    const ts = okxTs(Date.now() + await ensureVenueTime('okx', null, route));
    const fullPath = reqPath + (q ? '?' + q : '');
    const headers = {
      'OK-ACCESS-KEY': creds.key,
      'OK-ACCESS-SIGN': okxSign(creds.secret, ts, method, fullPath, bodyStr),
      'OK-ACCESS-TIMESTAMP': ts,
      'OK-ACCESS-PASSPHRASE': String(creds.pass || ''),
    };
    let r;
    try {
      r = await httpJson(OKX_HOST, method, reqPath, q, bodyStr || null, headers, route);
    } catch (e) { return transportFail(e, 'OKX'); }
    if (r.status === 429) return { ok: false, message: 'Rate limited by OKX — retry shortly' };
    let data;
    try { data = JSON.parse(r.text); } catch (e) {
      return { ok: false, message: 'OKX returned HTTP ' + r.status };
    }
    const code = String((data && data.code) != null ? data.code : '');
    if (code !== '0') {
      // Batch endpoints report per-row sCode/sMsg under data with code=1.
      const row = (Array.isArray(data && data.data) && data.data[0]) || {};
      const sc = String(row.sCode || '') || code;
      const sm = String(row.sMsg || (data && data.msg) || '');
      return { ok: false, message: okxErrorMessage(sc, sm) };
    }
    return { ok: true, data: data };
  }

  const okxCtCache = {};
  async function okxCtVal(symbol, route) {
    const c = okxCtCache[symbol];
    if (c && Date.now() - c.ts < PRODUCTS_TTL_MS) return c.v;
    try {
      const r = await httpJson(OKX_HOST, 'GET', '/api/v5/public/instruments',
                               formEnc([['instType', 'SWAP'], ['instId', symbol]]),
                               null, {}, route);
      const d = JSON.parse(r.text);
      const row = (((d || {}).data) || [])[0] || {};
      const v = bnNum(row.ctVal) || null;
      okxCtCache[symbol] = { ts: Date.now(), v: v };
      return v;
    } catch (e) { return null; }
  }

  async function execOkx(creds, intent, route) {
    if (!creds.pass) return { ok: false, message: 'OKX API passphrase missing — re-provision Native trading on this device' };
    const market = intent.market === 'spot' ? 'spot' : 'futures';
    const fetchPos = async () => {
      const r = await okxRequest(creds, 'GET', '/api/v5/account/positions',
                                 [['instType', 'SWAP']], null, route);
      if (!r.ok) return r;
      const ctMap = {};
      ctMap[intent.symbol] = await okxCtVal(intent.symbol, route);
      return { ok: true, rows: okxPositionRows(r.data, ctMap) };
    };
    async function place(mkt, symbol, side, ordType, qty, price, clOrdID, flags) {
      const f = flags || {};
      const t = String(ordType).toLowerCase();
      const isStop = t === 'stop' || t === 'stop_limit' || t === 'tp_market';
      const ct = mkt === 'futures' ? await okxCtVal(symbol, route) : null;
      if (isStop) {
        const body = okxAlgoBody(symbol, side, ordType, qty, price, f.trigger, clOrdID,
                                 { reduceOnly: !!f.reduceOnly,
                                   closeOnTrigger: !!f.closeOnTrigger, ctVal: ct });
        const r = await okxRequest(creds, 'POST', '/api/v5/trade/order-algo', null, body, route);
        if (!r.ok) return r;
        const rows = ((r.data || {}).data) || [];
        const aid = String((rows[0] || {}).algoId || '');
        return { ok: true, orderID: aid ? 'algo:' + aid : null, clOrdID: clOrdID };
      }
      const body = okxOrderBody(mkt, symbol, side, ordType, qty, price, clOrdID,
                                { reduceOnly: !!f.reduceOnly, ctVal: ct });
      const r = await okxRequest(creds, 'POST', '/api/v5/trade/order', null, body, route);
      if (!r.ok) return r;
      const rows = ((r.data || {}).data) || [];
      const oid = String((rows[0] || {}).ordId || '');
      return { ok: true, orderID: oid || null, clOrdID: clOrdID };
    }
    if (intent.op === 'order') {
      return place(market, intent.symbol, intent.side, intent.type,
                   intent.qty, intent.price, intent.clOrdID,
                   { reduceOnly: !!intent.reduceOnly, trigger: intent.trigger });
    }
    if (intent.op === 'cancel') {
      const oid = String(intent.orderID);
      let r;
      if (oid.indexOf('algo:') === 0) {
        r = await okxRequest(creds, 'POST', '/api/v5/trade/cancel-algos', null,
                             [{ instId: String(intent.symbol), algoId: oid.slice(5) }], route);
      } else {
        r = await okxRequest(creds, 'POST', '/api/v5/trade/cancel-order', null,
                             { instId: String(intent.symbol), ordId: oid }, route);
      }
      if (!r.ok) return r;
      return { ok: true, cancelled: intent.orderID };
    }
    if (intent.op === 'cancel_all') {
      // No blanket cancel-all on OKX: batch-cancel pending plain orders,
      // then sweep pending algo (stop) orders on futures.
      const instType = market === 'futures' ? 'SWAP' : 'SPOT';
      const ids = [];
      let after = '';
      for (let page = 0; page < 10; page++) {
        const params = [['instType', instType], ['limit', '100']];
        if (after) params.push(['after', after]);
        const r = await okxRequest(creds, 'GET', '/api/v5/trade/orders-pending', params, null, route);
        if (!r.ok) return r;
        const lst = ((r.data || {}).data) || [];
        for (const o of lst) {
          if (String((o || {}).instId || '') === String(intent.symbol)) {
            const oid = String(o.ordId || '');
            if (oid) ids.push(oid);
          }
        }
        if (lst.length < 100) break;
        after = String((lst[lst.length - 1] || {}).ordId || '');
        if (!after) break;
      }
      for (let i = 0; i < ids.length; i += 20) {
        const body = ids.slice(i, i + 20).map((oid) => ({ instId: String(intent.symbol), ordId: oid }));
        const r = await okxRequest(creds, 'POST', '/api/v5/trade/cancel-batch-orders', null, body, route);
        if (!r.ok) return r;
      }
      if (market === 'futures') {
        const aids = [];
        for (const ordType of ['trigger', 'conditional']) {
          let aft = '';
          for (let page = 0; page < 10; page++) {
            const params = [['ordType', ordType], ['limit', '100']];
            if (aft) params.push(['after', aft]);
            const r = await okxRequest(creds, 'GET', '/api/v5/trade/orders-algo-pending', params, null, route);
            if (!r.ok) return r;
            const lst = ((r.data || {}).data) || [];
            for (const o of lst) {
              if (String((o || {}).instType || 'SWAP') !== 'SWAP') continue;
              if (String((o || {}).instId || '') !== String(intent.symbol)) continue;
              const aid = String(o.algoId || '');
              if (aid) aids.push(aid);
            }
            if (lst.length < 100) break;
            aft = String((lst[lst.length - 1] || {}).algoId || '');
            if (!aft) break;
          }
        }
        for (let i = 0; i < aids.length; i += 10) {
          const body = aids.slice(i, i + 10).map((aid) => ({ instId: String(intent.symbol), algoId: aid }));
          const r = await okxRequest(creds, 'POST', '/api/v5/trade/cancel-algos', null, body, route);
          if (!r.ok) {
            if (okxCancelGone(r.message)) continue;   // gone-family: keep sweeping
            return r;
          }
        }
      }
      return { ok: true, cancelled: 'all' };
    }
    const pr = await findPosRetry(fetchPos, intent.symbol);
    if (!pr.ok) return pr;
    if (intent.op === 'close') {
      if (!pr.pos) return { ok: false, message: 'Position not found' };
      const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
      const r = await place('futures', pr.pos.symbol, side, 'market', pr.pos.size,
                            null, intent.clOrdID, { reduceOnly: true });
      if (!r.ok) return r;
      return { ok: true, orderID: r.orderID, clOrdID: intent.clOrdID };
    }
    if (!pr.pos) return { ok: false, message: 'No open position to protect' };
    const terr = sltpTriggerOk(intent.kind, pr.pos.side, intent.trigger, pr.pos.mark);
    if (terr) return { ok: false, message: terr };
    const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
    const ordType = intent.kind === 'sl' ? 'stop' : 'tp_market';
    const r = await place('futures', pr.pos.symbol, side, ordType, pr.pos.size,
                          null, intent.clOrdID,
                          { reduceOnly: true, trigger: intent.trigger, closeOnTrigger: true });
    if (!r.ok) return r;
    return { ok: true, kind: intent.kind, orderID: r.orderID, clOrdID: intent.clOrdID };
  }

  // --- #2153 Gate account push lane ---------------------------------------
  // Gate splits private data across TWO WS endpoints — spot
  // (wss://api.gateio.ws/ws/v4/) and USDT futures
  // (wss://fx-ws.gateio.ws/v4/ws/usdt) — so a session runs one scope per
  // socket (engine GatePrivateCache twin; Binance two-socket precedent).
  // Auth is PER-SUBSCRIBE: every private channel's subscribe frame carries
  // {method:'api_key', KEY, SIGN} with SIGN = HMAC-SHA512 over
  // 'channel=<ch>&event=subscribe&time=<t>' (gateWsSign). Futures channels
  // key on the numeric account uid ([uid,'!all']) resolved once per session
  // from /futures/usdt/accounts — a spot-only key has no futures account:
  // that loop parks on a long cool-down (fail-visible scope.err, never a
  // hot retry). usertrades is the ONLY fills source (no order-delta
  // reconstruction). Pending PRICE ORDERS (stop family, po:<id>) do NOT
  // ride any WS channel — the ack-time gateMutKick + push-kicked acct read
  // cover their badge latency (the read's price_orders leg is the truth);
  // a triggered stop then lands as a plain order on the orders channel.
  // Rides the proxy agent like all shell traffic (krWsDial).
  const GATE_PUSH_SPOT_URL = 'wss://api.gateio.ws/ws/v4/';
  const GATE_PUSH_FUT_URL = 'wss://fx-ws.gateio.ws/v4/ws/usdt';
  const GATE_PUSH_FILLS_CAP = 600;
  const gatePushSessions = {};
  const gatePushPend = {};
  let gatePushTimer = null;
  function gatePushFlush() {
    gatePushTimer = null;
    const evs = krPushDrain(gatePushPend, (key) => {
      const sess = gatePushSessions[key.slice(0, key.indexOf('|'))];
      if (!sess) return 0;
      return key.slice(key.indexOf('|') + 1) === 'spot' ? sess.sp.lseq : sess.fu.lseq;
    }, Date.now(), 'gate');
    for (const ev of evs) {
      try { pushLedgerCb(ev); } catch (e) { /* window gone */ }
      // a mutation observed on the push beat invalidates the acct-read memo
      // (Binance flush pattern) so the push-kicked read never serves stale.
      try { execAcctRead.bust('gate', ev.slot); } catch (e) { /* no memo */ }
      try { execAcctRead.markHot('gate'); } catch (e) { /* #2131 hot lane */ }
      tdiag('acct', 'gate_push', { s: ev.scope, q: ev.seq, k: ev.kinds.join(',') });
    }
    // push-beat local-blotter drain (HL pattern): fills land in the local
    // store on the flush itself (idempotent — lbDrain dedups by exec_id).
    try {
      for (const ev of evs) {
        if (ev && ev.kinds && ev.kinds.indexOf('fill') >= 0)
          lbDrain(String(ev.slot || 'gate'), 'gate');
      }
    } catch (e) { /* local store off — panel read drains later */ }
  }
  function gatePushSc(scope, kind, id, row) {
    if (!pushLedgerCb || !scope || !scope._pk) return;
    krPushMark(gatePushPend, scope._pk, kind, id, row);
    if (!gatePushTimer) {
      gatePushTimer = setTimeout(gatePushFlush, KR_PUSH_COALESCE_MS);
      if (gatePushTimer && typeof gatePushTimer.unref === 'function') gatePushTimer.unref();
    }
  }
  function gatePushScope(pk) {
    return { running: false, up: false, ws: null, err: null, lastMsg: 0,
             lseq: 0, seeded: false, fills: { rows: [], seen: {} }, _pk: pk };
  }
  function gatePushClose(slot) {
    const sess = gatePushSessions[slot];
    if (!sess) return;
    sess.closed = true;
    for (const sc of [sess.sp, sess.fu]) {
      try { if (sc.ws) sc.ws.terminate(); } catch (e) { /* gone */ }
      sc.ws = null; sc.up = false;
    }
    delete gatePushSessions[slot];
  }
  function gatePushCloseAll() {
    for (const k of Object.keys(gatePushSessions)) gatePushClose(k);
  }
  function gatePushEnsure(slot, creds, route) {
    if (!WSC || !creds || !creds.key) return null;
    slot = String(slot || 'gate');
    let sess = gatePushSessions[slot];
    if (sess && sess.tail !== creds.key) { gatePushClose(slot); sess = null; }
    if (!sess) {
      sess = gatePushSessions[slot] = {
        tail: creds.key, closed: false, route: route, creds: creds,
        uid: null, tOff: 0,
        sp: gatePushScope(slot + '|spot'),
        fu: gatePushScope(slot + '|fut'),
      };
    }
    sess.route = route;   // latest route pick wins for the next (re)dial
    sess.creds = creds;
    if (!sess.sp.running) gatePushLoop(slot, sess, 'spot');
    if (!sess.fu.running) gatePushLoop(slot, sess, 'fut');
    return sess;
  }
  async function gatePushSeed(sess, which) {
    // dedup-only seed: the usertrades channels have no snapshot frame, so
    // recent REST exec ids pre-mark the seen-set (a fill recorded by the
    // poll path milliseconds before the socket came up must not re-push).
    // Best-effort: a failed seed never blocks the stream (push is truth).
    const sc = which === 'fut' ? sess.fu : sess.sp;
    if (sc.seeded) return;
    sc.seeded = true;
    try {
      const reqPath = which === 'fut' ? '/futures/usdt/my_trades' : '/spot/my_trades';
      const r = await gateRequest(sess.creds, 'GET', reqPath,
                                  [['limit', '100']], null, sess.route);
      if (!r.ok) return;
      for (const f of (Array.isArray(r.data) ? r.data : [])) {
        const eid = f && f.id != null ? String(f.id) : '';
        if (eid) sc.fills.seen[eid] = 1;
      }
    } catch (e) { /* best-effort */ }
  }
  function gatePushLoop(slot, sess, which) {
    const sc = which === 'fut' ? sess.fu : sess.sp;
    sc.running = true;
    (async () => {
      let backoff = 2000;
      while (gatePushSessions[slot] === sess && !sess.closed) {
        const t0 = Date.now();
        try {
          // signer clock discipline (native-venue-time-sync): subscribe
          // frames stamp venue-synced seconds, never raw Date.now().
          sess.tOff = await ensureVenueTime('gate', null, sess.route);
          if (which === 'fut' && sess.uid == null) {
            const r = await gateRequest(sess.creds, 'GET', '/futures/usdt/accounts',
                                        null, null, sess.route);
            if (!r.ok) throw new Error(r.message || 'futures account read failed');
            const uid = Number((r.data || {}).user);
            if (!Number.isFinite(uid) || uid <= 0) throw new Error('futures account uid missing');
            sess.uid = uid;
          }
          await gatePushSeed(sess, which);
          await gatePushConn(slot, sess, which);
          if (Date.now() - t0 > 60000) backoff = 2000;   // productive conn resets
        } catch (e) {
          sc.err = 'Gate push: ' + ((e && e.message) || 'error');
          tdiag('acct', 'gate_push_err', { s: which, m: String(sc.err).slice(0, 120) });
          // spot-only key: no futures account is a STATE, not a transient —
          // park on a long cool-down (picks up a later futures opening
          // without hammering the endpoint at the hot ladder).
          if (which === 'fut' && String((e && e.message) || '').indexOf('futures account') >= 0) {
            backoff = 600000;
          }
        }
        sc.up = false; sc.ws = null;
        if (sess.closed || gatePushSessions[slot] !== sess) break;
        await krWsSleep(backoff);
        backoff = Math.min(backoff * 2, backoff >= 600000 ? 600000 : 60000);
      }
      sc.running = false;
    })().catch(() => { sc.running = false; });
  }
  function gatePushConn(slot, sess, which) {
    return new Promise((resolve, reject) => {
      const mk = which === 'fut' ? 'futures' : 'spot';
      const ws = krWsDial(which === 'fut' ? GATE_PUSH_FUT_URL : GATE_PUSH_SPOT_URL, sess.route);
      if (!ws) { reject(new Error('proxy agent unavailable')); return; }
      const sc = which === 'fut' ? sess.fu : sess.sp;
      sc.ws = ws;
      let settled = false;
      let acked = 0;
      const expect = which === 'fut' ? 4 : 3;
      const done = (err) => {
        if (settled) return;
        settled = true;
        clearInterval(kaT);
        sc.up = false;
        try { ws.terminate(); } catch (e) { /* closed */ }
        if (err) reject(err); else resolve();
      };
      // Gate idle-closes quiet conns — app-level <mkt>.ping every 20s keeps
      // it live; a 90s frame gap tears down for a clean redial.
      const kaT = setInterval(() => {
        try { ws.send(JSON.stringify({ time: Number(venueStampSec(sess.tOff)), channel: mk + '.ping' })); }
        catch (e) { /* dying */ }
        if (Date.now() - (sc.lastMsg || 0) > 90000) done(new Error('stream stalled'));
      }, 20000);
      if (kaT && typeof kaT.unref === 'function') kaT.unref();
      const sub = (channel, payload) => {
        const tsec = Number(venueStampSec(sess.tOff));
        const fr = { time: tsec, channel: channel, event: 'subscribe',
                     auth: { method: 'api_key', KEY: sess.creds.key,
                             SIGN: gateWsSign(sess.creds.secret, channel, 'subscribe', tsec) } };
        if (payload != null) fr.payload = payload;
        ws.send(JSON.stringify(fr));
      };
      ws.on('open', () => {
        sc.lastMsg = Date.now();
        try {
          if (which === 'fut') {
            const uid = String(sess.uid);
            sub('futures.orders', [uid, '!all']);
            sub('futures.usertrades', [uid, '!all']);
            sub('futures.positions', [uid, '!all']);
            sub('futures.balances', [uid]);
          } else {
            sub('spot.orders', ['!all']);
            sub('spot.usertrades', ['!all']);
            sub('spot.balances');
          }
        } catch (e) { done(e); return; }
      });
      ws.on('ping', () => { sc.lastMsg = Date.now(); });
      ws.on('message', (buf) => {
        sc.lastMsg = Date.now();
        let msg = null;
        try { msg = JSON.parse(buf.toString()); } catch (e) { return; }
        const ev = String((msg && msg.event) || '');
        if (ev === 'subscribe') {
          if (msg.error) {
            done(new Error('subscribe rejected: ' + String((msg.error && msg.error.message) || msg.error)));
            return;
          }
          acked++;
          if (acked >= expect && !sc.up) {
            sc.up = true; sc.err = null;
            tdiag('acct', 'gate_push_up', { s: slot + '|' + which });
          }
          return;
        }
        if (ev !== 'update') return;   // pong/other control frames
        try { gatePushEvApply(sc, mk, msg); } catch (e) { /* row skipped */ }
      });
      ws.on('error', (e) => done(e || new Error('ws error')));
      ws.on('close', () => done(new Error('closed')));
    });
  }
  function gatePushEvApply(sc, mk, msg) {
    const ch = String((msg && msg.channel) || '');
    const res = msg && msg.result;
    const rows = Array.isArray(res) ? res
      : (res && typeof res === 'object' ? [res] : []);
    if (!ch || !rows.length) return;
    if (ch === mk + '.usertrades') {
      for (const f of rows) {
        const eid = f && f.id != null ? String(f.id) : '';
        if (!eid || sc.fills.seen[eid]) continue;
        sc.fills.seen[eid] = 1;
        // RAW usertrades row rides the push (contract/currency_pair, size/
        // amount+side, price, fee/fee_currency/point_fee, create_time_ms all
        // included — fee passthrough). Never slim it; the scope key routes
        // the market panel-side (spot vs fut sockets never mix).
        sc.fills.rows.push(f);
        if (sc.fills.rows.length > GATE_PUSH_FILLS_CAP) {
          sc.fills.rows.splice(0, sc.fills.rows.length - GATE_PUSH_FILLS_CAP);
        }
        lbSrcTouch(sc.fills);   // #2230
        krLseq(sc); gatePushSc(sc, 'fill', eid, f);
        if (mk === 'futures') { krLseq(sc); gatePushSc(sc, 'pos'); }   // a fill moves the position
      }
      return;
    }
    if (ch === mk + '.orders') {
      // engine gate_order_apply twin: spot rows carry `event`
      // (put/update=open, finish=gone); futures rows carry `status`
      // (open vs finished). Open rows ride as REST-shaped order rows —
      // the panel's gateAcctOrderRow reads both shapes directly.
      for (const o of rows) {
        const oid = o && o.id != null ? String(o.id) : '';
        if (!oid) continue;
        let isOpen;
        if (mk === 'futures') {
          isOpen = String((o && o.status) || 'open') === 'open';
        } else {
          const oev = String((o && o.event) || '');
          isOpen = oev ? (oev === 'put' || oev === 'update')
                       : String((o && o.status) || 'open') === 'open';
        }
        if (isOpen) { krLseq(sc); gatePushSc(sc, 'order', null, o); }
        else { krLseq(sc); gatePushSc(sc, 'ordgone', oid); }
      }
      return;
    }
    if (ch === 'futures.positions' && mk === 'futures') {
      // flat rows (size 0) ride too — the panel's gateAcctPosRow returns
      // null for them and the upsert removes the posrow that beat.
      for (const p of rows) { krLseq(sc); gatePushSc(sc, 'pos', null, p); }
      return;
    }
    if (ch === mk + '.balances') {
      for (const b of rows) { krLseq(sc); gatePushSc(sc, 'bal', null, b); }
    }
  }
  // Optimistic mutation stamp at the order-send/cancel ack sites (Kraken/
  // Binance/Bybit pattern): the WS echo lands ~100ms later, but the local
  // bump makes the badge/posrow read fire immediately after the REST ack.
  // Market-scoped — gate order ids are per-market sequences (spot and
  // futures id spaces may collide; the scope key keeps tombstones honest).
  function gateMutKick(slot, kind, oid, market) {
    const sess = gatePushSessions[String(slot || 'gate')];
    if (!sess) return;
    const sc = market === 'spot' ? sess.sp : sess.fu;
    if (kind === 'ordgone' && oid) {
      krLseq(sc); gatePushSc(sc, 'ordgone', String(oid));
    } else {
      krLseq(sc); gatePushSc(sc, 'order');
    }
  }

  // --- Gate --------------------------------------------------------------------
  async function gateRequest(creds, method, reqPath, params, body, route) {
    const q = params && params.length ? formEnc(params) : '';
    const bodyStr = body != null ? canonJson(body) : '';
    const ts = venueStampSec(await ensureVenueTime('gate', null, route));
    const fullPath = GATE_API_PREFIX + reqPath;
    const headers = {
      'KEY': creds.key,
      'Timestamp': ts,
      'SIGN': gateSign(creds.secret, method, fullPath, q, bodyStr, ts),
    };
    let r;
    try {
      r = await httpJson(GATE_HOST, method, fullPath, q, bodyStr || null, headers, route);
    } catch (e) { return transportFail(e, 'Gate'); }
    if (r.status === 429) return { ok: false, message: 'Rate limited by Gate — retry shortly' };
    let data = null;
    try { data = r.text ? JSON.parse(r.text) : null; } catch (e) { data = null; }
    if (r.status >= 400) {
      const label = data && (data.label || data.detail) ? String(data.label || '') : '';
      const msg = String((data && (data.message || data.detail)) || '');
      return { ok: false, message: gateErrorMessage(label, msg || ('HTTP ' + r.status)) };
    }
    return { ok: true, data: data };
  }

  const gateMultCache = {};
  async function gateMult(symbol, route) {
    const c = gateMultCache[symbol];
    if (c && Date.now() - c.ts < PRODUCTS_TTL_MS) return c.v;
    try {
      const r = await httpJson(GATE_HOST, 'GET',
                               GATE_API_PREFIX + '/futures/usdt/contracts/' + encodeURIComponent(String(symbol)),
                               '', null, {}, route);
      const d = JSON.parse(r.text);
      const v = bnNum((d || {}).quanto_multiplier) || null;
      gateMultCache[symbol] = { ts: Date.now(), v: v };
      return v;
    } catch (e) { return null; }
  }

  async function execGate(creds, intent, route) {
    const market = intent.market === 'spot' ? 'spot' : 'futures';
    const fetchPos = async () => {
      const r = await gateRequest(creds, 'GET', '/futures/usdt/positions', null, null, route);
      if (!r.ok) return r;
      const multMap = {};
      multMap[intent.symbol] = await gateMult(intent.symbol, route);
      return { ok: true, rows: gatePositionRows(r.data, multMap) };
    };
    async function place(mkt, symbol, side, ordType, qty, price, clOrdID, flags) {
      const f = flags || {};
      const t = String(ordType).toLowerCase();
      const isStop = t === 'stop' || t === 'stop_limit' || t === 'tp_market';
      const mult = mkt === 'futures' ? await gateMult(symbol, route) : null;
      if (isStop) {
        const body = gatePoBody(symbol, side, ordType, qty, price, f.trigger, clOrdID,
                                { reduceOnly: !!f.reduceOnly,
                                  closeOnTrigger: !!f.closeOnTrigger, multiplier: mult });
        const r = await gateRequest(creds, 'POST', '/futures/usdt/price_orders', null, body, route);
        if (!r.ok) return r;
        const pid = String((r.data || {}).id || '');
        return { ok: true, orderID: pid ? 'po:' + pid : null, clOrdID: clOrdID };
      }
      const body = gateOrderBody(mkt, symbol, side, ordType, qty, price, clOrdID,
                                 { reduceOnly: !!f.reduceOnly, multiplier: mult });
      const reqPath = mkt === 'spot' ? '/spot/orders' : '/futures/usdt/orders';
      const r = await gateRequest(creds, 'POST', reqPath, null, body, route);
      if (!r.ok) return r;
      const oid = String((r.data || {}).id || '');
      return { ok: true, orderID: oid || null, clOrdID: clOrdID };
    }
    if (intent.op === 'order') {
      return place(market, intent.symbol, intent.side, intent.type,
                   intent.qty, intent.price, intent.clOrdID,
                   { reduceOnly: !!intent.reduceOnly, trigger: intent.trigger });
    }
    if (intent.op === 'cancel') {
      const oid = String(intent.orderID);
      let r;
      if (oid.indexOf('po:') === 0) {
        r = await gateRequest(creds, 'DELETE',
                              '/futures/usdt/price_orders/' + oid.slice(3), null, null, route);
      } else if (market === 'futures') {
        r = await gateRequest(creds, 'DELETE', '/futures/usdt/orders/' + oid, null, null, route);
      } else {
        r = await gateRequest(creds, 'DELETE', '/spot/orders/' + oid,
                              [['currency_pair', String(intent.symbol)]], null, route);
      }
      if (!r.ok) return r;
      return { ok: true, cancelled: intent.orderID };
    }
    if (intent.op === 'cancel_all') {
      if (market === 'spot') {
        const r = await gateRequest(creds, 'DELETE', '/spot/orders',
                                    [['currency_pair', String(intent.symbol)], ['account', 'spot']],
                                    null, route);
        if (!r.ok) return r;
        return { ok: true, cancelled: 'all' };
      }
      const r = await gateRequest(creds, 'DELETE', '/futures/usdt/orders',
                                  [['contract', String(intent.symbol)]], null, route);
      if (!r.ok) return r;
      // Sweep pending price orders (stop family) too — terminal rule.
      const rp = await gateRequest(creds, 'DELETE', '/futures/usdt/price_orders',
                                   [['contract', String(intent.symbol)]], null, route);
      if (!rp.ok && !gateCancelGone(rp.message)) return rp;
      return { ok: true, cancelled: 'all' };
    }
    const pr = await findPosRetry(fetchPos, intent.symbol);
    if (!pr.ok) return pr;
    if (intent.op === 'close') {
      if (!pr.pos) return { ok: false, message: 'Position not found' };
      const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
      const r = await place('futures', pr.pos.symbol, side, 'market', pr.pos.size,
                            null, intent.clOrdID, { reduceOnly: true });
      if (!r.ok) return r;
      return { ok: true, orderID: r.orderID, clOrdID: intent.clOrdID };
    }
    if (!pr.pos) return { ok: false, message: 'No open position to protect' };
    const terr = sltpTriggerOk(intent.kind, pr.pos.side, intent.trigger, pr.pos.mark);
    if (terr) return { ok: false, message: terr };
    const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
    const ordType = intent.kind === 'sl' ? 'stop' : 'tp_market';
    const r = await place('futures', pr.pos.symbol, side, ordType, pr.pos.size,
                          null, intent.clOrdID,
                          { reduceOnly: true, trigger: intent.trigger, closeOnTrigger: true });
    if (!r.ok) return r;
    return { ok: true, kind: intent.kind, orderID: r.orderID, clOrdID: intent.clOrdID };
  }

  // --- #2247 Bitget account push lane --------------------------------------
  // Bitget serves EVERY private channel on ONE socket
  // (wss://ws.bitget.com/v2/ws/private) — engine BitgetPrivateCache twin.
  // Login is a single op frame whose signature is HMAC-SHA256/base64 over
  // '<epoch SECONDS>GET/user/verify' (bitgetWsLoginSig): the REST signer's
  // MILLISECOND stamp is rejected here. Then five subscribes, per instType:
  // USDT-FUTURES account/positions/orders + SPOT account/orders.
  // FILLS ride TWO channels and converge on ONE dedup set:
  //   • the dedicated private `fill` channel (SPOT + USDT-FUTURES) — one
  //     unambiguous row per fill, and
  //   • the ORDERS channel deltas (a row carrying tradeId with a positive
  //     this-fill quantity IS one fill; accBaseVolume is the running order
  //     total), exactly like bitget_order_apply.
  // #2251: the orders lane alone recorded NOTHING across a twelve-order live
  // session. Both lanes now push into the same side-inclusive tradeId ring,
  // so whichever arrives first wins and the second is a no-op — one row, one
  // chime. The `fill` subscribe is a BONUS: a venue that rejects it leaves
  // the socket up on the other four channels (expect stays 5).
  // ONE socket, but the panel lane stays MARKET-SCOPED (two scopes, sp/fu,
  // one lseq each): Bitget order ids are per-market sequences, so a
  // both-markets tombstone sweep could bury an unrelated order (gate rule).
  // Every fill delta rides the slot's REST-poll fill RING (bgFillPush), so
  // the local blotter drain, the acct read's lbFills graft and the push
  // event all dedupe against ONE side-inclusive tradeId seen-set — a fill
  // the poll recorded milliseconds earlier can never re-push, and a pushed
  // read serves rows the store already has instead of racing them.
  // Pending PLAN orders (stop family, 'pl:<id>') do NOT ride these channels
  // (they live on the separate orders-algo channel the engine deliberately
  // never connects to): the ack-time bgMutKick plus the push-kicked acct
  // read cover their badge latency, exactly like Gate's price orders. An
  // honest poll beats pretending the lane covers them.
  // Keepalive is the literal text 'ping' → 'pong' (Bitget drops a conn
  // quiet for 30s). Rides the proxy agent like all shell traffic (krWsDial).
  const BG_PUSH_WS_URL = 'wss://ws.bitget.com/v2/ws/private';
  const BG_PUSH_PING_MS = 25000;
  const BG_PUSH_STALL_MS = 90000;
  // engine _BITGET_OPEN_STATUSES twin — anything else removes the badge.
  const BG_PUSH_OPEN_ST = { live: 1, new: 1, init: 1, partially_filled: 1, partial_fill: 1 };
  const bgPushSessions = {};
  const bgPushPend = {};
  let bgPushTimer = null;
  function bgPushFlush() {
    bgPushTimer = null;
    const evs = krPushDrain(bgPushPend, (key) => {
      const sess = bgPushSessions[key.slice(0, key.indexOf('|'))];
      if (!sess) return 0;
      return key.slice(key.indexOf('|') + 1) === 'spot' ? sess.sp.lseq : sess.fu.lseq;
    }, Date.now(), 'bitget');
    for (const ev of evs) {
      try { pushLedgerCb(ev); } catch (e) { /* window gone */ }
      // a mutation observed on the push beat invalidates the acct-read memo
      // (Binance flush pattern) so the push-kicked read never serves stale.
      try { execAcctRead.bust('bitget', ev.slot); } catch (e) { /* no memo */ }
      try { execAcctRead.markHot('bitget'); } catch (e) { /* #2131 hot lane */ }
      tdiag('acct', 'bitget_push', { s: ev.scope, q: ev.seq, k: ev.kinds.join(',') });
    }
    // push-beat local-blotter drain (HL/Gate pattern): fills land in the
    // local store on the flush itself (idempotent — lbDrain dedups by
    // exec_id), so the read that follows serves recorded rows.
    try {
      for (const ev of evs) {
        if (ev && ev.kinds && ev.kinds.indexOf('fill') >= 0)
          lbDrain(String(ev.slot || 'bitget'), 'bitget');
      }
    } catch (e) { /* local store off — panel read drains later */ }
  }
  function bgPushSc(scope, kind, id, row) {
    if (!pushLedgerCb || !scope || !scope._pk) return;
    krPushMark(bgPushPend, scope._pk, kind, id, row);
    if (!bgPushTimer) {
      bgPushTimer = setTimeout(bgPushFlush, KR_PUSH_COALESCE_MS);
      if (bgPushTimer && typeof bgPushTimer.unref === 'function') bgPushTimer.unref();
    }
  }
  function bgPushScope(pk) {
    return { lseq: 0, posSyms: null, _pk: pk };
  }
  function bgPushClose(slot) {
    const sess = bgPushSessions[slot];
    if (!sess) return;
    sess.closed = true;
    try { if (sess.ws) sess.ws.terminate(); } catch (e) { /* gone */ }
    sess.ws = null; sess.up = false;
    delete bgPushSessions[slot];
  }
  function bgPushCloseAll() {
    for (const k of Object.keys(bgPushSessions)) bgPushClose(k);
  }
  function bgPushEnsure(slot, creds, route) {
    if (!WSC || !creds || !creds.key || !creds.pass) return null;
    slot = String(slot || 'bitget');
    let sess = bgPushSessions[slot];
    if (sess && sess.tail !== creds.key) { bgPushClose(slot); sess = null; }
    if (!sess) {
      sess = bgPushSessions[slot] = {
        slot: slot, tail: creds.key, closed: false, route: route, creds: creds,
        running: false, up: false, ws: null, err: null, lastMsg: 0, tOff: 0,
        sp: bgPushScope(slot + '|spot'),
        fu: bgPushScope(slot + '|fut'),
      };
    }
    sess.route = route;   // latest route pick wins for the next (re)dial
    sess.creds = creds;
    if (!sess.running) bgPushLoop(slot, sess);
    return sess;
  }
  function bgPushLoop(slot, sess) {
    sess.running = true;
    (async () => {
      let backoff = 2000;
      while (bgPushSessions[slot] === sess && !sess.closed) {
        const t0 = Date.now();
        try {
          // signer clock discipline (native-venue-time-sync): the login
          // frame stamps venue-synced seconds, never raw Date.now().
          sess.tOff = await ensureVenueTime('bitget', null, sess.route);
          await bgPushConn(slot, sess);
          if (Date.now() - t0 > 60000) backoff = 2000;   // productive conn resets
        } catch (e) {
          sess.err = 'Bitget push: ' + ((e && e.message) || 'error');
          tdiag('acct', 'bitget_push_err', { m: String(sess.err).slice(0, 120) });
        }
        sess.up = false; sess.ws = null;
        if (sess.closed || bgPushSessions[slot] !== sess) break;
        await krWsSleep(backoff);
        backoff = Math.min(backoff * 2, 60000);
      }
      sess.running = false;
    })().catch(() => { sess.running = false; });
  }
  function bgPushConn(slot, sess) {
    return new Promise((resolve, reject) => {
      const ws = krWsDial(BG_PUSH_WS_URL, sess.route);
      if (!ws) { reject(new Error('proxy agent unavailable')); return; }
      sess.ws = ws;
      let settled = false;
      let acked = 0;
      const expect = 5;
      const done = (err) => {
        if (settled) return;
        settled = true;
        clearInterval(kaT);
        sess.up = false;
        try { ws.terminate(); } catch (e) { /* closed */ }
        if (err) reject(err); else resolve();
      };
      // literal-text keepalive (public-WS convention): 'ping' → 'pong'.
      // A 90s frame gap tears down for a clean redial.
      const kaT = setInterval(() => {
        try { ws.send('ping'); } catch (e) { /* dying */ }
        if (Date.now() - (sess.lastMsg || 0) > BG_PUSH_STALL_MS) done(new Error('stream stalled'));
      }, BG_PUSH_PING_MS);
      if (kaT && typeof kaT.unref === 'function') kaT.unref();
      ws.on('open', () => {
        sess.lastMsg = Date.now();
        // #2251 per-CONNECTION seed state. `action:'snapshot'` is NOT a
        // reliable delta discriminator on this venue (Bitget's own contract
        // Order-Channel example labels an ordinary order push "snapshot"),
        // so the seed rule is positional/temporal, not payload-declared:
        //  • fseen — first frame of a (channel, market) pair seeds the
        //    full-list channels (positions/account) exactly as the old
        //    action test intended;
        //  • connT — venue-clock time at connect, so a fill replayed from a
        //    subscribe snapshot can be told from a live one by its own
        //    timestamp instead of by a field the venue mislabels.
        sess.fseen = {};
        sess.connT = Date.now() + (sess.tOff || 0);
        // #2262 per-CONNECTION, per-market liveness of the dedicated `fill`
        // channel (see bgFillLaneOwns) and the LOCAL open stamp its pending
        // grace measures against — connT is venue-clock, this one is not.
        sess.fillCh = {};
        sess.openT = Date.now();
        sess.xl = null;
        try {
          const tsec = String(venueStampSec(sess.tOff));
          ws.send(JSON.stringify({ op: 'login', args: [{
            apiKey: sess.creds.key, passphrase: String(sess.creds.pass || ''),
            timestamp: tsec, sign: bitgetWsLoginSig(sess.creds.secret, tsec),
          }] }));
        } catch (e) { done(e); return; }
      });
      ws.on('ping', () => { sess.lastMsg = Date.now(); });
      ws.on('message', (buf) => {
        sess.lastMsg = Date.now();
        const txt = buf.toString();
        if (txt === 'pong' || txt === 'ping') return;   // literal keepalive
        let msg = null;
        try { msg = JSON.parse(txt); } catch (e) { return; }
        const evn = String((msg && msg.event) || '');
        if (evn === 'error') {
          // #2251 a refused `fill` subscribe must NOT tear down the socket:
          // that channel is additive, and killing the connection would take
          // orders/positions/account down with it and redial forever.
          const earg = (msg && msg.arg) || {};
          if (String(earg.channel || '') === 'fill') {
            // #2262 …and THIS market's fills go back to the orders lane, so
            // a refusal costs nothing but the per-fill payload's precision.
            const emk = bgFillChMark(sess, earg, -1);
            tdiag('acct', 'bitget_push_nofill',
                  { s: slot, mk: emk || '?', m: String((msg && msg.msg) || '').slice(0, 80) });
            return;
          }
          done(new Error('bitget ws: ' + String((msg && msg.msg) || 'error')));
          return;
        }
        if (evn === 'login') {
          try {
            for (const a of [
              { instType: 'USDT-FUTURES', channel: 'account', coin: 'default' },
              { instType: 'USDT-FUTURES', channel: 'positions', instId: 'default' },
              { instType: 'USDT-FUTURES', channel: 'orders', instId: 'default' },
              { instType: 'SPOT', channel: 'account', coin: 'default' },
              { instType: 'SPOT', channel: 'orders', instId: 'default' },
              // #2251 dedicated per-fill channel, both markets. NOT counted
              // in `expect`: if the venue refuses it the lane still comes up
              // and the orders deltas + REST poll carry the fills.
              { instType: 'USDT-FUTURES', channel: 'fill', instId: 'default' },
              { instType: 'SPOT', channel: 'fill', instId: 'default' },
            ]) ws.send(JSON.stringify({ op: 'subscribe', args: [a] }));
          } catch (e) { done(e); return; }
          return;
        }
        if (evn === 'subscribe') {
          // #2262 an acked `fill` subscribe takes OWNERSHIP of that market's
          // fills: the orders lane stops ingesting them (its badge/status
          // work is untouched), because the two lanes stamp DIFFERENT
          // tradeIds on one execution and the ring's id set cannot collapse
          // them — every fill was recorded, and chimed, twice.
          const sarg = (msg && msg.arg) || {};
          if (String(sarg.channel || '') === 'fill') {
            // …unless the ack is LATE, in which case the market has already
            // fallen back and keeps the orders lane (st reports which).
            const smk = bgFillChMark(sess, sarg, 1);
            tdiag('acct', 'bitget_push_fillch',
                  { s: slot, mk: smk || '?', st: bgFillChSt(sess, smk) });
          }
          acked++;
          if (acked >= expect && !sess.up) {
            sess.up = true; sess.err = null;
            tdiag('acct', 'bitget_push_up', { s: slot });
          }
          return;
        }
        if (evn) return;   // unknown control frame
        try { bgPushEvApply(sess, msg); } catch (e) { /* row skipped */ }
      });
      ws.on('error', (e) => done(e || new Error('ws error')));
      ws.on('close', () => done(new Error('closed')));
    });
  }
  // #2251 how much of a fill's own timestamp still counts as "live" at
  // connect. Rows older than this on the first frames of a connection are
  // recorded into the store (the local blotter wants them) but raise no
  // push event, so a subscribe snapshot can never chime historical fills.
  const BG_PUSH_FRESH_MS = 120000;
  // One value-free shape line per (channel, market) per session: WHICH keys
  // a REAL Bitget fill-bearing frame carries. The previous fill branch was
  // built on assumed field names and matched zero of twelve live orders —
  // this makes the next field log decisive instead of another guess. Names
  // only, never values (diag rule).
  const BG_SHAPE_KEYS = ['tradeId', 'orderId', 'baseVolume', 'accBaseVolume', 'size',
    'amount', 'quoteVolume', 'notional', 'fillPrice', 'price', 'priceAvg', 'side',
    'tradeSide', 'posSide', 'posMode', 'fillFee', 'fillFeeCoin', 'feeDetail', 'profit',
    'status', 'instId', 'symbol', 'cTime', 'fillTime', 'uTime'];
  function bgPushShapeDiag(sess, ch, mk, row) {
    if (!row || typeof row !== 'object') return;
    const k = ch + '|' + mk;
    if (!sess.shape) sess.shape = {};
    if (sess.shape[k]) return;
    sess.shape[k] = 1;
    const have = [];
    for (const n of BG_SHAPE_KEYS) {
      const v = row[n];
      if (v !== undefined && v !== null && v !== '') have.push(n);
    }
    tdiag('acct', 'bitget_push_shape', { s: sess.slot, ch: ch, mk: mk, keys: have.join(',') });
  }
  // #2251 THIS fill's quantity, from whichever field the venue actually
  // used. The orders channel names it `baseVolume` (`size` there is the
  // ORDER's size, quote-denominated on a spot buy — never the fill); the
  // dedicated fill channel names it `baseVolume` on futures and `size` on
  // spot. Order matters: baseVolume first, so an orders delta can never
  // read the order's quote `size` by accident.
  function bgFillQty(o) {
    const b = parseFloat(o && o.baseVolume);
    if (Number.isFinite(b) && b > 0) return b;
    const s = parseFloat(o && o.size);
    return (Number.isFinite(s) && s > 0) ? s : 0;
  }
  // A fill-BEARING row on either lane: a venue trade id plus a positive
  // THIS-fill quantity (engine bitget_order_apply rule).
  function bgFillRow(o) {
    return !!(o && o.tradeId != null && String(o.tradeId) && bgFillQty(o) > 0);
  }
  // #2262 --- ONE fill source per market ------------------------------------
  // The dedicated `fill` channel and the orders channel stamp DIFFERENT
  // tradeIds on the SAME execution (a live session logged ids two apart at
  // the same instant, same side), so the ring's side-inclusive tradeId set
  // can never collapse them: every fill was recorded twice — doubling the
  // replayed position size and the chime — and the orders-lane copy carried
  // a suppressed (zero) fee, which is what dragged break-even off. Ownership
  // is the fix, not more dedup. The `fill` channel is also the streaming
  // twin of /api/v2/{mix,spot}/…/fills, so its ids are the ones the REST
  // poll, the backfill and the device store already hold.
  //
  // Per-connection, per-market state: 1 = subscribe acked (that channel owns
  // the market's fills), -1 = the venue refused it (the orders lane ingests,
  // exactly as before this task), 0 = neither answered yet. A PENDING
  // channel keeps the orders lane suppressed for a short grace — the ack is
  // milliseconds behind the login and an ingest inside that window is
  // precisely the double being removed — and past the grace it is treated as
  // refused, so a silently-dropped subscribe can never leave the market
  // without a push fill source.
  const BG_FILL_ACK_GRACE_MS = 10000;
  function bgArgMk(arg) {
    const it = String(((arg || {}).instType) || '').toUpperCase();
    if (it === 'SPOT') return 'spot';
    return it ? 'futures' : '';
  }
  function bgFillAckLate(sess) {
    return (Date.now() - ((sess && sess.openT) || 0)) >= BG_FILL_ACK_GRACE_MS;
  }
  // Per-market state machine, MONOTONE for the life of one connection:
  // pending → owned (ack inside the grace) or pending → fallback (refusal, or
  // a grace that ran out), and NEVER back. A late ack is demoted to fallback
  // on purpose: the orders lane may already have recorded fills for this
  // market, and because the two lanes stamp different tradeIds on the same
  // execution, anything the fill stream then re-delivers (its own replay, or
  // simply the next fills while the orders lane is still ingesting) records
  // and chimes a second time — the very defect being fixed. The reconnect,
  // which resets fillCh and openT, is what re-decides ownership.
  function bgFillChSet(sess, mk, st) {
    if (!mk || !sess) return '';
    if (!sess.fillCh) sess.fillCh = {};
    if (st > 0 && ((sess.fillCh[mk] | 0) < 0 || bgFillAckLate(sess))) st = -1;
    sess.fillCh[mk] = st;
    return mk;
  }
  function bgFillChMark(sess, arg, st) {
    // An unidentifiable market stays PENDING rather than guessing: the grace
    // resolves it to the orders lane, whereas a wrong guess either re-creates
    // the double or silences the market for the whole session.
    return bgFillChSet(sess, bgArgMk(arg), st);
  }
  function bgFillChSt(sess, mk) { return (((sess && sess.fillCh) || {})[mk]) | 0; }
  function bgFillLaneOwns(sess, mk) {
    const st = bgFillChSt(sess, mk);
    if (st) return st > 0;
    if (!bgFillAckLate(sess)) return true;      // pending, inside the grace
    bgFillChSet(sess, mk, -1);                  // …and the timeout LATCHES
    return false;
  }
  // Can THIS row's fee be read as THIS fill's fee? A row recorded with a
  // quantity but a suppressed fee is worse than no row: the replay carries
  // the size while break-even divides the real fees by an inflated net. Two
  // independent things have to hold, and BOTH failures produce the identical
  // zero out of the fee readers:
  //  1. READABLE — the row must actually carry a fee the readers can parse.
  //     A flat `fillFee` (spot deltas + the spot `fill` channel) is per-fill
  //     by construction; otherwise `feeDetail` must yield at least one
  //     numeric entry (list `totalFee`/`fee`, or the object form's
  //     `totalFee`) exactly as lbBgFillFee/bgPushFillFeeQ read it. Missing,
  //     empty, non-numeric or unparseable-JSON fee detail is fee UNKNOWN,
  //     not fee zero. An EXPLICIT zero — or a rebate — parses fine and stays
  //     admissible: those are real venue values, not a suppression.
  //  2. PER-FILL — no `accBaseVolume` ⇒ a per-fill payload (the `fill`
  //     channel, the REST fills endpoints) ⇒ its feeDetail is this fill's
  //     own. An ORDERS-channel delta carries the running order total and an
  //     order-CUMULATIVE feeDetail, trustworthy only when this fill is the
  //     whole order so far.
  // Condition (2) is the lbBgFillFee / bgPushFillFeeQ suppression itself, and
  // the pair is test-pinned: an untrusted row must be exactly one those
  // readers answer 0 for, or a row would be recorded precisely when its fee
  // is zeroed. A withheld row is not lost — the authoritative per-fill
  // payload (fill channel / REST fills poll, which writes the ring directly)
  // carries the same execution with its fee, and `nf` in bitget_push_xlane
  // counts every withholding so a live log can prove it.
  function bgFeeTrusted(o) {
    const r = o || {};
    if (Number.isFinite(parseFloat(r.fillFee))) return true;
    let fd = r.feeDetail;
    if (typeof fd === 'string') { try { fd = JSON.parse(fd); } catch (e) { fd = null; } }
    let any = false;
    if (Array.isArray(fd)) {
      for (const d0 of fd) {
        const d = d0 || {};
        if (Number.isFinite(parseFloat(d.totalFee)) || Number.isFinite(parseFloat(d.fee))) {
          any = true; break;
        }
      }
    } else if (fd && typeof fd === 'object') any = Number.isFinite(parseFloat(fd.totalFee));
    if (!any) return false;
    if (r.accBaseVolume === undefined || r.accBaseVolume === null) return true;
    const bv = parseFloat(r.baseVolume), acc = parseFloat(r.accBaseVolume);
    return Number.isFinite(bv) && Number.isFinite(acc)
      && Math.abs(bv - acc) <= 1e-12 * Math.max(1, Math.abs(acc));
  }
  // Cross-lane duplicate census. The lanes disagree on tradeId, so the only
  // previous evidence of the overlap was order-count-versus-fill-count
  // arithmetic done by hand on a live log. This counts it directly, on the
  // fields the two lanes DO agree on for one execution: orderId, side, this
  // fill's quantity and its price (numeric-normalised, so formatting can
  // never hide a pair). Two identical partials of one order at one price
  // share a signature, so `x` is an UPPER bound — and an upper bound of zero
  // is exactly the proof this task needs. Counts only ever leave the
  // process: a diag never carries venue values.
  const BG_XL_SUM_MS = 30000;
  const BG_XL_KEYS = 512;
  function bgXSig(mk, o) {
    const oid = String((o && o.orderId) != null ? o.orderId : '');
    const q = bgFillQty(o);
    if (!oid || !(q > 0)) return '';
    const px = parseFloat((o && (o.priceAvg || o.price || o.fillPrice)) || 0) || 0;
    return mk + '|' + oid + '|' + String((o && o.side) || '').toLowerCase()
      + '|' + q + '|' + px;
  }
  function bgXLane(sess) {
    // t starts at creation, so the first line lands one interval in rather
    // than every fresh connection flushing a line on its first frame.
    if (!sess.xl) sess.xl = { seen: {}, keys: [], f: 0, o: 0, x: 0, sup: 0, nf: 0,
                              lt: 0, d: 0, t: Date.now() };
    return sess.xl;
  }
  function bgXLaneMark(sess, mk, lane, o) {
    const X = bgXLane(sess);
    const fl = lane === 'fill';
    if (fl) X.f++; else X.o++;
    X.d = 1;
    const sig = bgXSig(mk, o);
    if (!sig) return;
    let e = X.seen[sig];
    if (!e) {
      e = X.seen[sig] = { f: 0, o: 0, p: 0 };
      X.keys.push(sig);
      if (X.keys.length > BG_XL_KEYS) {
        for (const k of X.keys.splice(0, X.keys.length - BG_XL_KEYS)) delete X.seen[k];
      }
    }
    if (fl) e.f++; else e.o++;
    const pair = Math.min(e.f, e.o);
    if (pair > e.p) { e.p = pair; X.x++; }
  }
  // Coalesced summary (push-apply-latency-diag family): the LINE's ts is the
  // flush moment, the counters are the connection's running totals —
  // f/o = fill-bearing rows per lane, x = executions seen on BOTH,
  // sup = orders-lane rows the fill channel owned, nf = rows withheld for an
  // untrustworthy fee, lt = fill-channel rows dropped because the market had
  // already fallen back to the orders lane (a late ack — see bgFillChSet).
  function bgXLaneSum(sess) {
    const X = sess && sess.xl;
    if (!X || !X.d) return;
    const now = Date.now();
    if (now - (X.t || 0) < BG_XL_SUM_MS) return;
    X.t = now; X.d = 0;
    tdiag('acct', 'bitget_push_xlane',
          { s: sess.slot, f: X.f, o: X.o, x: X.x, sup: X.sup, nf: X.nf, lt: X.lt });
  }
  // #2268 --- cross-lane FEE adoption ---------------------------------------
  // Ownership (#2262) decides which lane RECORDS an execution. It must not
  // also decide where that execution's FEE comes from. Bitget's SPOT `fill`
  // channel carries no flat fee field at all (live shape: tradeId, orderId,
  // size, amount, priceAvg, side, feeDetail, symbol, cTime, uTime) and its
  // feeDetail resolves to a ZERO quote cost, while the SUPPRESSED orders-lane
  // twin of the same execution carries the flat per-fill `fillFee` +
  // `fillFeeCoin` the venue really charged. A 209s live session recorded nine
  // spot fills, every one at fee 0, so spot break-even sat exactly on the
  // average entry — while futures, whose fill rows DO carry a readable
  // feeDetail, was correct throughout the same session.
  //
  // The lanes stamp different tradeIds, so the twin is matched on what they
  // DO agree on: bgXSig — market|orderId|side|this-fill-qty|price, the same
  // signature the duplicate census already pairs executions with.
  //
  // Both arrival orders are covered (the frames ride ONE burst; either can be
  // first):
  //   orders first → the flat fee is stashed and adopted AT ingest, so the
  //     ring row, the device store and the pushed panel row all carry it;
  //   fill first  → the row records immediately (never delayed — the chime,
  //     the blotter and the spot basis ride it) and is remembered; the twin
  //     then patches that ring row IN PLACE (the store normalizes at drain
  //     time, so it drains with the fee) and re-pushes the same fid, which
  //     the panel merges over the fee-less row. One fid = one chime latch, so
  //     a patched re-push can never ring twice.
  // Futures is untouched by construction: adoption fires only for a row whose
  // OWN fee records as zero, and only a spot orders-delta carries a flat fee.
  const BG_FEE_WAIT_MS = 15000;   // pending/stash lifetime — one burst is ms
  const BG_FEE_KEYS = 256;
  // The flat PER-FILL fee, or null. `fillFee` is per-fill by construction
  // (lbBgFillFee's first rule) — the same delta's feeDetail is the order
  // CUMULATIVE list and is never what gets adopted.
  function bgFeeFlat(o) {
    const v = parseFloat(o && o.fillFee);
    if (!Number.isFinite(v)) return null;
    return { fee: String(o.fillFee), ccy: String((o && o.fillFeeCoin) || '') };
  }
  // The quote COST this row will actually be recorded with, through the very
  // readers that record it (lbBgFillFee plus lbNormBitgetFill's sign flip and
  // base-coin conversion — mirrored verbatim). 0 = "records as free", no
  // matter which shape the row used to say so.
  function bgFeeCost(o, mk) {
    const ff = lbBgFillFee(o || {});
    let c = -Number(ff.fee || 0);
    if (!Number.isFinite(c)) return 0;
    const sym = String((o && (o.symbol || o.instId)) || '').toUpperCase();
    const ccy = String(ff.ccy || '');
    if (mk === 'spot' && ccy && sym.slice(-ccy.length) !== ccy) {
      c = c * (Number(lbNum((o && (o.priceAvg || o.price || o.fillPrice)) || 0)) || 0);
    }
    return c > 0 ? c : 0;
  }
  function bgFeeX(sess) {
    if (!sess.fx) sess.fx = { m: {}, keys: [], sp: null, fu: null };
    return sess.fx;
  }
  function bgFeeCnt(X, mk) {
    const k = mk === 'spot' ? 'sp' : 'fu';
    if (!X[k]) X[k] = { ad: 0, px: 0, sv: 0, mv: 0, zf: 0, d: 0, t: Date.now() };
    return X[k];
  }
  function bgFeeSlot(sess, sig) {
    const X = bgFeeX(sess);
    let e = X.m[sig];
    if (!e) {
      e = X.m[sig] = { f: null, p: null, ts: Date.now() };
      X.keys.push(sig);
      if (X.keys.length > BG_FEE_KEYS) {
        for (const k of X.keys.splice(0, X.keys.length - BG_FEE_KEYS)) {
          const ev = X.m[k];
          if (ev && ev.p) bgFeeZero(sess, ev.p.mk, ev.p.o);
          delete X.m[k];
        }
      }
    }
    return e;
  }
  // #2268 a fill recorded at zero fee is NEVER silent. One value-free line
  // per market names the keys the row did carry (BG_SHAPE_KEYS allowlist —
  // names only, never values), so the next field log says WHY instead of
  // being another guess, and the coalesced counter line below says how often.
  function bgFeeZero(sess, mk, o) {
    const C = bgFeeCnt(bgFeeX(sess), mk);
    C.zf++; C.d = 1;
    if (!sess.nfz) sess.nfz = {};
    if (sess.nfz[mk]) return;
    sess.nfz[mk] = 1;
    const have = [];
    for (const n of BG_SHAPE_KEYS) {
      const v = o && o[n];
      if (v !== undefined && v !== null && v !== '') have.push(n);
    }
    tdiag('acct', 'bitget_push_nofee', { s: sess.slot, mk: mk, keys: have.join(',') });
  }
  // A fee-less fill row takes the twin's stashed flat fee, before the ring
  // write, so nothing downstream ever sees the zero.
  function bgFeeAdopt(sess, mk, o) {
    const sig = bgXSig(mk, o);
    if (!sig) return false;
    const e = bgFeeX(sess).m[sig];
    const f = e && e.f;
    if (!f) return false;
    o.fillFee = f.fee; o.fillFeeCoin = f.ccy;
    e.f = null;
    const C = bgFeeCnt(bgFeeX(sess), mk); C.ad++; C.d = 1;
    return true;
  }
  // Recorded, still fee-less: remember the RING's own row object so the twin
  // can complete it in place. No signature = nothing can ever complete it.
  function bgFeePend(sess, sc, mk, o) {
    const sig = bgXSig(mk, o);
    if (!sig) { bgFeeZero(sess, mk, o); return; }
    const e = bgFeeSlot(sess, sig);
    e.ts = Date.now();
    e.p = { o: o, sc: sc, mk: mk, slot: sess.slot,
            fid: String(o.tradeId) + ':' + String(o.side || '').toLowerCase() };
  }
  // DURABLE half of the in-place patch. Patching the ring row only helps a
  // row the drain has not reached yet: the device store merges exactly once
  // per fill key, so a row already drained would keep its zero fee through
  // every later drain, every replay and every restart (the panel's blotter,
  // its net and the spot break-even all read the STORE, not the ring). The
  // stored row is therefore corrected in place — the lbMigrateBgCase recipe:
  //   • the per-group replay cache keys on (rows, first key, last key), and
  //     the payload cache on the rows ARRAY IDENTITY — both are blind to an
  //     in-place field edit, so each is invalidated explicitly (one group,
  //     never the whole store: a fill must not cost a full-store replay);
  //   • a snapshot is folded promptly. A snapshot serializes the LIVE rows,
  //     and journal replay merges exactly-once behind it, so the older
  //     fee-zero journal line can never win over the corrected snapshot.
  // The drain cursors are deliberately left alone — nothing vanished, and the
  // ring row this corrects has already been consumed.
  // → 1 stored row corrected, 0 nothing to do (not drained yet / deleted),
  //   -1 the store holds the fill but the correction could not reach it.
  function bgFeeStoreFix(slot, mk, o) {
    if (!_lbStore) return 0;        // never loaded ⇒ nothing was drained ⇒ nothing to fix
    const nf = lbNormBitgetFill(o, mk);
    if (!nf) return 0;
    const k = lbFillKey(nf);
    if (!k) return 0;
    const sc = lbScopeIn(_lbStore, slot);
    if (sc.del && sc.del[k]) return 0;            // deleted locally — leave it deleted
    const hit = {};
    const n = lbFeeFixIn(sc, k, nf.fee, hit);
    if (n < 0) return 0;                          // already carries this fee
    if (!n) return (sc.seen && sc.seen[k]) ? -1 : 0;
    if (sc._rep && sc._rep.g) delete sc._rep.g[lbGroupKey(hit.row || nf)];
    delete _lbTrCache[slot];
    lbSnapSoon(0);
    return 1;
  }
  // The suppressed orders-lane twin offers its flat per-fill fee: adopted by
  // a fill row still to come, or patched into the one already recorded.
  function bgFeeOffer(sess, mk, o) {
    const f = bgFeeFlat(o);
    if (!f) return;
    const sig = bgXSig(mk, o);
    if (!sig) return;
    const e = bgFeeSlot(sess, sig);
    e.ts = Date.now();
    const p = e.p;
    if (!p) { e.f = f; return; }                  // the fill row is not here yet
    e.p = null;
    p.o.fillFee = f.fee; p.o.fillFeeCoin = f.ccy; // ring row, patched in place
    const C = bgFeeCnt(bgFeeX(sess), mk); C.px++; C.d = 1;
    // …and the copy the device store already took, which no drain can revisit
    const st = bgFeeStoreFix(p.slot || sess.slot, p.mk, p.o);
    if (st > 0) C.sv++; else if (st < 0) C.mv++;
    krLseq(p.sc); bgPushSc(p.sc, 'fill', p.fid, p.o);
  }
  // Coalesced fee-provenance line — sibling of bitget_push_xlane, which stays
  // byte-identical. ad = fees adopted from the twin at ingest, px = rows
  // patched afterwards, sv = stored rows corrected with them, mv = stored rows
  // the correction could not reach, zf = rows that stayed at zero (the honest
  // failures — mv and zf are what a field log must never see above 0).
  function bgFeeSum(sess, now) {
    const X = sess && sess.fx;
    if (!X) return;
    for (const mk of ['spot', 'futures']) {
      const C = X[mk === 'spot' ? 'sp' : 'fu'];
      if (!C || !C.d) continue;
      if ((now - (C.t || 0)) < BG_XL_SUM_MS) continue;
      C.t = now; C.d = 0;
      tdiag('acct', 'bitget_push_fee',
            { s: sess.slot, mk: mk, ad: C.ad, px: C.px, sv: C.sv, mv: C.mv, zf: C.zf });
    }
  }
  // Timer-free expiry: every frame sweeps. A pending row whose twin never
  // came is counted (and named once) rather than passing as a real zero.
  function bgFeeSweep(sess, now) {
    const X = sess && sess.fx;
    if (!X) return;
    now = now || Date.now();
    const keep = [];
    for (const k of X.keys) {
      const e = X.m[k];
      if (!e) continue;
      if ((now - (e.ts || 0)) < BG_FEE_WAIT_MS) { keep.push(k); continue; }
      if (e.p) bgFeeZero(sess, e.p.mk, e.p.o);
      delete X.m[k];
    }
    X.keys = keep;
    bgFeeSum(sess, now);
  }
  // One fill row → ring + push event, shared by BOTH lanes so they can never
  // double-record or double-chime: the ring's side-inclusive tradeId seen-set
  // is the single dedup set, and bgFillPush returns 0 for a row the other
  // lane (or the REST poll) already took.
  function bgFillIngest(sess, sc, mk, ch, o) {
    const tid = o && o.tradeId != null ? String(o.tradeId) : '';
    if (!bgFillRow(o)) return;
    bgPushShapeDiag(sess, ch, mk, o);
    // #2262 quantity without a trustworthy fee is not recorded at all — the
    // per-fill payload owns that execution (see bgFeeTrusted).
    if (!bgFeeTrusted(o)) { bgXLane(sess).nf++; return; }
    // #2268 the lane owns the ROW, never the fee: a row that would record as
    // free takes the twin's flat per-fill fee (stashed, or patched below).
    // The cost is re-read AFTER adoption, so a twin whose own fee also reads
    // as free is still counted and named rather than passing as a real zero.
    let cost = bgFeeCost(o, mk);
    if (!(cost > 0) && bgFeeAdopt(sess, mk, o)) cost = bgFeeCost(o, mk);
    const feeless = !(cost > 0);
    const F = mk === 'spot' ? bgFillRing(sess.slot).sp : bgFillRing(sess.slot).fu;
    if (bgFillPush(F, [o]) <= 0) return;          // already recorded — no event
    if (feeless) bgFeePend(sess, sc, mk, o);      // the ring holds THIS object
    // Recorded either way; only the EVENT (badge + chime) is age-gated.
    const ts = bgFillTs(o);
    if (ts && ts < ((sess.connT || 0) - BG_PUSH_FRESH_MS)) return;
    // fid namespace = '<tradeId>:<side>' — byte-identical to the panel's
    // lbFill/state-fill eid, so ONE chime latch covers the pushed fill and
    // the same fill arriving on the next acct read (a '|' ring key here
    // would double-chime every fill).
    krLseq(sc); bgPushSc(sc, 'fill', tid + ':' + String(o.side || '').toLowerCase(), o);
    if (mk === 'futures') { krLseq(sc); bgPushSc(sc, 'pos'); }   // a fill moves the position
  }
  function bgPushEvApply(sess, msg) {
    const arg = (msg && msg.arg) || {};
    const ch = String(arg.channel || '');
    if (!ch) return;
    const mk = String(arg.instType || '').toUpperCase() === 'SPOT' ? 'spot' : 'futures';
    const sc = mk === 'spot' ? sess.sp : sess.fu;
    const rows = Array.isArray(msg && msg.data) ? msg.data : [];
    // #2251 first frame of this (channel, market) on THIS connection = the
    // subscribe snapshot. The old test read msg.action === 'snapshot', but
    // Bitget labels ordinary order pushes "snapshot" too — which is exactly
    // why every live fill was silently seeded instead of recorded.
    if (!sess.fseen) sess.fseen = {};
    const fk = ch + '|' + mk;
    const snap = !sess.fseen[fk];
    sess.fseen[fk] = 1;
    // Dedicated per-fill channel: one unambiguous row per fill, no order
    // bookkeeping to disentangle. Age-gated, not snapshot-gated (see above).
    if (ch === 'fill') {
      // #2262 ownership is one-way per connection (see bgFillChSet). If this
      // market's fills already fell back to the orders lane, a fill stream
      // that starts talking afterwards must NOT record alongside it — the
      // lanes stamp different tradeIds, so every overlapping execution would
      // land twice. Count what that costs; the orders lane has it covered.
      const owns = bgFillLaneOwns(sess, mk);
      for (const o of rows) {
        if (!bgFillRow(o)) continue;
        bgXLaneMark(sess, mk, 'fill', o);
        if (owns) bgFillIngest(sess, sc, mk, ch, o);
        else bgXLane(sess).lt++;
      }
      bgXLaneSum(sess);
      bgFeeSweep(sess);
      return;
    }
    if (ch === 'orders') {
      // #2262 the dedicated `fill` channel owns this market's fills while it
      // is live; the orders lane then drives ONLY badges and status
      // transitions, exactly as it does today. A refused (or never-answered)
      // fill subscribe hands fill ingestion straight back here.
      const owned = bgFillLaneOwns(sess, mk);
      for (const o of rows) {
        // fill delta (engine bitget_order_apply rule): tradeId present and a
        // positive THIS-fill quantity. The RAW row rides the push —
        // lbNormBitgetFill already reads the WS orders-delta shape, so the
        // panel/local-blotter normalizers need no new case.
        if (bgFillRow(o)) {
          // the census runs on BOTH lanes even where this one no longer
          // records, so a live log can PROVE the overlap is gone
          bgXLaneMark(sess, mk, 'orders', o);
          // #2268 a suppressed row is not a useless row: its flat per-fill
          // fee is the one the spot `fill` channel never sends.
          if (owned) { bgXLane(sess).sup++; bgFeeOffer(sess, mk, o); }
          else bgFillIngest(sess, sc, mk, ch, o);
        }
        const oid = o && o.orderId != null ? String(o.orderId) : '';
        if (snap || !oid) continue;
        const st = String((o && o.status) || '').toLowerCase();
        if (BG_PUSH_OPEN_ST[st]) { krLseq(sc); bgPushSc(sc, 'order', null, o); }
        else { krLseq(sc); bgPushSc(sc, 'ordgone', oid); }
      }
      bgXLaneSum(sess);
      bgFeeSweep(sess);
      return;
    }
    if (ch === 'positions' && mk === 'futures') {
      // FULL-LIST semantics (engine bitget_position_apply): every payload is
      // the whole position book, and a closed position simply disappears —
      // an empty data:[] frame is the "everything is flat" delta. Symbols
      // that dropped out push a synthetic flat row so the panel removes the
      // posrow (and sweeps its reduce-only stops) on THIS beat instead of
      // waiting for a poll to notice the absence.
      const seen = {};
      for (const p of rows) {
        const sym = String((p && (p.instId || p.symbol)) || '');
        if (sym) seen[sym] = 1;
        if (!snap) { krLseq(sc); bgPushSc(sc, 'pos', null, p); }
      }
      if (!snap) {
        for (const sym of Object.keys(sc.posSyms || {})) {
          if (seen[sym]) continue;
          krLseq(sc); bgPushSc(sc, 'pos', null, { instId: sym, symbol: sym, total: '0' });
        }
      }
      sc.posSyms = seen;
      return;
    }
    if (ch === 'account' && !snap) {
      for (const b of rows) { krLseq(sc); bgPushSc(sc, 'bal', null, b); }
    }
  }
  // Optimistic mutation stamp at the order-send/cancel ack sites (Kraken/
  // Binance/Bybit/Gate pattern): the WS echo lands ~100ms later, but the
  // local bump makes the badge/posrow read fire immediately after the REST
  // ack — and it is the ONLY lane pending plan orders have, since they
  // never stream. Market-scoped: Bitget order ids are per-market sequences.
  function bgMutKick(slot, kind, oid, market) {
    const sess = bgPushSessions[String(slot || 'bitget')];
    if (!sess) return;
    const sc = market === 'spot' ? sess.sp : sess.fu;
    if (kind === 'ordgone' && oid) {
      krLseq(sc); bgPushSc(sc, 'ordgone', String(oid));
    } else {
      krLseq(sc); bgPushSc(sc, 'order');
    }
  }

  // --- Bitget ------------------------------------------------------------------
  async function bitgetRequest(creds, method, reqPath, params, body, route) {
    const q = params && params.length ? formEnc(params) : '';
    const bodyStr = body != null ? canonJson(body) : '';
    const ts = venueStampMs(await ensureVenueTime('bitget', null, route));
    const fullPath = reqPath + (q ? '?' + q : '');
    const headers = {
      'ACCESS-KEY': creds.key,
      'ACCESS-SIGN': bitgetSign(creds.secret, ts, method, fullPath, bodyStr),
      'ACCESS-TIMESTAMP': ts,
      'ACCESS-PASSPHRASE': String(creds.pass || ''),
    };
    let r;
    try {
      r = await httpJson(BITGET_HOST, method, reqPath, q, bodyStr || null, headers, route);
    } catch (e) { return transportFail(e, 'Bitget'); }
    if (r.status === 429) return { ok: false, message: 'Rate limited by Bitget — retry shortly' };
    let data;
    try { data = JSON.parse(r.text); } catch (e) {
      return { ok: false, message: 'Bitget returned HTTP ' + r.status };
    }
    const code = String((data && data.code) != null ? data.code : '');
    if (code !== '00000') {
      return { ok: false, message: bitgetErrorMessage(code, String((data && data.msg) || '')) };
    }
    return { ok: true, data: data };
  }

  async function execBitget(creds, intent, route) {
    if (!creds.pass) return { ok: false, message: 'Bitget API passphrase missing — re-provision Native trading on this device' };
    const market = intent.market === 'spot' ? 'spot' : 'futures';
    const fetchPos = async () => {
      const r = await bitgetRequest(creds, 'GET', '/api/v2/mix/position/all-position',
                                    [['productType', BITGET_PRODUCT_TYPE], ['marginCoin', 'USDT']],
                                    null, route);
      if (!r.ok) return r;
      return { ok: true, rows: bitgetPositionRows(r.data) };
    };
    async function cancelPlan(symbol, planId, planType) {
      // cancel-plan-order needs the planType GROUP back — probe both when
      // the caller doesn't know it (bare pl: id from the panel).
      const tries = (planType === 'normal_plan' || planType === 'profit_loss')
        ? [planType] : ['normal_plan', 'profit_loss'];
      let lastErr = null;
      for (const pt of tries) {
        const body = { symbol: String(symbol), productType: BITGET_PRODUCT_TYPE,
                       marginCoin: 'USDT', orderIdList: [{ orderId: String(planId) }],
                       planType: pt };
        const r = await bitgetRequest(creds, 'POST', '/api/v2/mix/order/cancel-plan-order',
                                      null, body, route);
        if (r.ok) return { ok: true, cancelled: 'pl:' + String(planId) };
        lastErr = r;
      }
      return lastErr || { ok: false, message: 'Cancel failed' };
    }
    async function place(mkt, symbol, side, ordType, qty, price, clOrdID, flags) {
      const f = flags || {};
      const t = String(ordType).toLowerCase();
      const isStop = t === 'stop' || t === 'stop_limit' || t === 'tp_market';
      if (isStop) {
        const body = bitgetPlanBody(symbol, side, ordType, qty, price, f.trigger, clOrdID,
                                    { reduceOnly: !!f.reduceOnly,
                                      closeOnTrigger: !!f.closeOnTrigger });
        const reqPath = f.closeOnTrigger ? '/api/v2/mix/order/place-tpsl-order'
                                         : '/api/v2/mix/order/place-plan-order';
        const r = await bitgetRequest(creds, 'POST', reqPath, null, body, route);
        if (!r.ok) return r;
        const oid = String((((r.data || {}).data) || {}).orderId || '');
        return { ok: true, orderID: oid ? 'pl:' + oid : null, clOrdID: clOrdID };
      }
      const body = bitgetOrderBody(mkt, symbol, side, ordType, qty, price, clOrdID,
                                   { reduceOnly: !!f.reduceOnly });
      const reqPath = mkt === 'futures' ? '/api/v2/mix/order/place-order'
                                        : '/api/v2/spot/trade/place-order';
      const r = await bitgetRequest(creds, 'POST', reqPath, null, body, route);
      if (!r.ok) return r;
      const oid = String((((r.data || {}).data) || {}).orderId || '');
      return { ok: true, orderID: oid || null, clOrdID: clOrdID };
    }
    async function cancelOne(mkt, symbol, orderId) {
      if (mkt === 'futures') {
        return bitgetRequest(creds, 'POST', '/api/v2/mix/order/cancel-order', null,
                             { symbol: String(symbol), productType: BITGET_PRODUCT_TYPE,
                               orderId: String(orderId) }, route);
      }
      return bitgetRequest(creds, 'POST', '/api/v2/spot/trade/cancel-order', null,
                           { symbol: String(symbol), orderId: String(orderId) }, route);
    }
    if (intent.op === 'order') {
      return place(market, intent.symbol, intent.side, intent.type,
                   intent.qty, intent.price, intent.clOrdID,
                   { reduceOnly: !!intent.reduceOnly, trigger: intent.trigger });
    }
    if (intent.op === 'cancel') {
      const oid = String(intent.orderID);
      if (oid.indexOf('pl:') === 0) {
        const r = await cancelPlan(intent.symbol, oid.slice(3), null);
        if (!r.ok) return r;
        return { ok: true, cancelled: intent.orderID };
      }
      const r = await cancelOne(market, intent.symbol, oid);
      if (!r.ok) return r;
      return { ok: true, cancelled: intent.orderID };
    }
    if (intent.op === 'cancel_all') {
      // List-and-cancel per symbol (no dependable blanket cancel-all).
      const ids = [];
      let after = '';
      for (let page = 0; page < 10; page++) {
        const params = market === 'futures'
          ? [['productType', BITGET_PRODUCT_TYPE], ['limit', '100']]
          : [['limit', '100']];
        if (after) params.push(['idLessThan', after]);
        const reqPath = market === 'futures' ? '/api/v2/mix/order/orders-pending'
                                             : '/api/v2/spot/trade/unfilled-orders';
        const r = await bitgetRequest(creds, 'GET', reqPath, params, null, route);
        if (!r.ok) return r;
        const d = (r.data || {}).data;
        const lst = (d && !Array.isArray(d)) ? (d.entrustedList || []) : (d || []);
        for (const o of Array.isArray(lst) ? lst : []) {
          if (String((o || {}).symbol || '') !== String(intent.symbol)) continue;
          const oid = String(o.orderId || '');
          if (oid) ids.push(oid);
        }
        if (!Array.isArray(lst) || lst.length < 100) break;
        after = String((lst[lst.length - 1] || {}).orderId || '');
        if (!after) break;
      }
      for (const oid of ids) {
        const r = await cancelOne(market, intent.symbol, oid);
        if (!r.ok) {
          if (bitgetCancelGone(r.message)) continue;
          return r;
        }
      }
      if (market === 'futures') {
        // Sweep pending plan (stop-family) orders too — terminal rule.
        const plans = [];
        for (const planType of ['normal_plan', 'profit_loss']) {
          let aft = '';
          for (let page = 0; page < 10; page++) {
            const params = [['productType', BITGET_PRODUCT_TYPE],
                            ['planType', planType], ['limit', '100']];
            if (aft) params.push(['idLessThan', aft]);
            const r = await bitgetRequest(creds, 'GET', '/api/v2/mix/order/orders-plan-pending',
                                          params, null, route);
            if (!r.ok) return r;
            const d = (r.data || {}).data;
            const lst = (d && !Array.isArray(d)) ? (d.entrustedList || []) : (d || []);
            for (const o of Array.isArray(lst) ? lst : []) {
              if (String((o || {}).symbol || '') !== String(intent.symbol)) continue;
              const pid = String(o.orderId || '');
              if (pid) plans.push([pid, String(o.planType || '') || null]);
            }
            if (!Array.isArray(lst) || lst.length < 100) break;
            aft = String((lst[lst.length - 1] || {}).orderId || '');
            if (!aft) break;
          }
        }
        for (const pp of plans) {
          const r = await cancelPlan(intent.symbol, pp[0], pp[1]);
          if (!r.ok) {
            if (bitgetCancelGone(r.message)) continue;
            return r;
          }
        }
      }
      return { ok: true, cancelled: 'all' };
    }
    const pr = await findPosRetry(fetchPos, intent.symbol);
    if (!pr.ok) return pr;
    if (intent.op === 'close') {
      if (!pr.pos) return { ok: false, message: 'Position not found' };
      const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
      const r = await place('futures', pr.pos.symbol, side, 'market', pr.pos.size,
                            null, intent.clOrdID, { reduceOnly: true });
      if (!r.ok) return r;
      return { ok: true, orderID: r.orderID, clOrdID: intent.clOrdID };
    }
    if (!pr.pos) return { ok: false, message: 'No open position to protect' };
    const terr = sltpTriggerOk(intent.kind, pr.pos.side, intent.trigger, pr.pos.mark);
    if (terr) return { ok: false, message: terr };
    const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
    const ordType = intent.kind === 'sl' ? 'stop' : 'tp_market';
    const r = await place('futures', pr.pos.symbol, side, ordType, pr.pos.size,
                          null, intent.clOrdID,
                          { reduceOnly: true, trigger: intent.trigger, closeOnTrigger: true });
    if (!r.ok) return r;
    return { ok: true, kind: intent.kind, orderID: r.orderID, clOrdID: intent.clOrdID };
  }

  // --- #2272 KuCoin account push lane --------------------------------------
  // KuCoin is the only native venue whose private streams live on TWO hosts
  // with TWO clocks: spot rides api.kucoin.com, futures api-futures.kucoin.com,
  // and each needs its OWN signed bullet + its own socket. The session
  // therefore runs two independent connection loops (sp/fu) under one slot,
  // each with its own scope/lseq — order id spaces are per-market here too, so
  // a both-markets tombstone sweep could bury an unrelated order (gate rule).
  //
  // Handshake, per host:
  //   POST /api/v1/bullet-private (signed) → { token, instanceServers:[{
  //   endpoint, pingInterval }] } → dial endpoint?token=…&connectId=… →
  //   {type:'welcome'} → subscribe frames → {type:'ack'} each.
  // Keepalive is APP-LEVEL JSON ({id,type:'ping'} → {type:'pong'}); KuCoin
  // drops a socket ~18s without one and WS protocol frames do NOT count, so
  // the cadence comes from the bullet's own pingInterval (kcPingMs: 60% of
  // it, clamped 5..16s).
  //
  // Channels (essential ones are counted in `expect`; the rest are BONUS — a
  // venue that refuses one leaves the socket up on the others):
  //   spot    /spotMarket/tradeOrdersV2   orders + `match` fill deltas
  //           /account/balance            wallet deltas
  //   futures /contractMarket/tradeOrders orders + `match` fill deltas
  //           /contractAccount/wallet     wallet deltas
  //           /contractMarket/advancedOrders  (bonus) untriggered STOPs —
  //             they never appear on tradeOrders, so without this the stop
  //             chips would still wait for a poll
  //           /contract/position:<sym>    (bonus, per symbol) venue-truth
  //             position rows; KuCoin has no all-symbols position channel, so
  //             the set is seeded from the acct read's own positions and from
  //             every futures symbol the lane sees, capped.
  //
  // FILL OWNERSHIP (#2272 step 2). A `match` delta carries NO fee and no
  // realized PnL, and a fill recorded with a size but a zeroed fee is worse
  // than no row (bgFeeTrusted rule: the replay carries the quantity while
  // break-even divides real fees by an inflated net). So the two lanes split
  // by capability, not by preference:
  //   • the REST fills poll (lbKcLive) RECORDS — its rows carry the venue's
  //     own fee, and it shares the `tradeId` id space with the match delta,
  //     so the ring's side-inclusive seen-set makes recording exactly-once;
  //   • the acked `match` lane EMITS the push event (badge, chime, posrow) at
  //     stream latency and kicks an immediate catch-up poll, which records
  //     the same execution WITH its fee and re-pushes the SAME fid so the
  //     panel merges the complete row over the fee-less one.
  // Emission ownership is per-connection and per-market and MONOTONE:
  // pending → owned (ack inside the grace) or → fallback (refusal, or a grace
  // that ran out), never back. Under fallback the poll emits too, so a market
  // is never left without a lane. One fid ('<tradeId>:<side>' — side-INCLUSIVE
  // or a self-match's two legs collapse into one row) = one chime latch, so
  // neither the enrichment re-push nor the poll can ring an execution twice.
  const KC_PUSH_STALL_MS = 60000;
  const KC_PUSH_FRESH_MS = 120000;
  const KC_FILL_ACK_GRACE_MS = 10000;
  const KC_PUSH_POS_CAP = 32;         // per-symbol position subs are bounded
  const KC_PUSH_CATCHUP_MS = 400;     // debounce for the fee-enrichment poll
  // engine kc_*_ws_apply event vocabulary — anything else removes the badge.
  const KC_PUSH_OPEN_EV = { open: 1, update: 1, match: 1 };
  const kcPushSessions = {};
  const kcPushPend = {};
  let kcPushTimer = null;
  let kcPushMsgId = 0;
  function kcPushNextId() { return 'ntk' + (++kcPushMsgId); }
  function kcPushFlush() {
    kcPushTimer = null;
    const evs = krPushDrain(kcPushPend, (key) => {
      const sess = kcPushSessions[key.slice(0, key.indexOf('|'))];
      if (!sess) return 0;
      return key.slice(key.indexOf('|') + 1) === 'spot' ? sess.sp.lseq : sess.fu.lseq;
    }, Date.now(), 'kucoin');
    for (const ev of evs) {
      try { pushLedgerCb(ev); } catch (e) { /* window gone */ }
      try { execAcctRead.bust('kucoin', ev.slot); } catch (e) { /* no memo */ }
      try { execAcctRead.markHot('kucoin'); } catch (e) { /* hot lane */ }
      tdiag('acct', 'kucoin_push', { s: ev.scope, q: ev.seq, k: ev.kinds.join(',') });
    }
    // push-beat local-blotter drain (HL/Gate/Bitget pattern): fills land in
    // the local store on the flush itself (idempotent — lbDrain dedups by
    // exec_id), so the read that follows serves recorded rows.
    try {
      for (const ev of evs) {
        if (ev && ev.kinds && ev.kinds.indexOf('fill') >= 0)
          lbDrain(String(ev.slot || 'kucoin'), 'kucoin');
      }
    } catch (e) { /* local store off — panel read drains later */ }
  }
  function kcPushSc(scope, kind, id, row) {
    if (!pushLedgerCb || !scope || !scope._pk) return;
    krPushMark(kcPushPend, scope._pk, kind, id, row);
    if (!kcPushTimer) {
      kcPushTimer = setTimeout(kcPushFlush, KR_PUSH_COALESCE_MS);
      if (kcPushTimer && typeof kcPushTimer.unref === 'function') kcPushTimer.unref();
    }
  }
  function kcPushScope(pk, mk) {
    return { lseq: 0, mk: mk, _pk: pk, ws: null, up: false, running: false,
             lastMsg: 0, subT: null, fseen: null, connT: 0, openT: 0,
             fillCh: 0, posSyms: null, posWant: {}, posSub: {}, nf: 0, lt: 0 };
  }
  function kcPushScopeReset(sc) {
    sc.ws = null; sc.up = false; sc.subT = null; sc.fseen = null;
    sc.connT = 0; sc.openT = 0; sc.fillCh = 0; sc.posSyms = null; sc.posSub = {};
  }
  function kcPushClose(slot) {
    const sess = kcPushSessions[slot];
    if (!sess) return;
    sess.closed = true;
    for (const sc of [sess.sp, sess.fu]) {
      try { if (sc.ws) sc.ws.terminate(); } catch (e) { /* gone */ }
      kcPushScopeReset(sc);
    }
    delete kcPushSessions[slot];
  }
  function kcPushCloseAll() {
    for (const k of Object.keys(kcPushSessions)) kcPushClose(k);
  }
  function kcPushEnsure(slot, creds, route) {
    if (!WSC || !creds || !creds.key || !creds.pass) return null;
    slot = String(slot || 'kucoin');
    let sess = kcPushSessions[slot];
    if (sess && sess.tail !== creds.key) { kcPushClose(slot); sess = null; }
    if (!sess) {
      sess = kcPushSessions[slot] = {
        slot: slot, tail: creds.key, closed: false, route: route, creds: creds,
        err: null, cu: {},
        sp: kcPushScope(slot + '|spot', 'spot'),
        fu: kcPushScope(slot + '|fut', 'futures'),
      };
    }
    sess.route = route;   // latest route pick wins for the next (re)dial
    sess.creds = creds;
    for (const sc of [sess.sp, sess.fu]) if (!sc.running) kcPushLoop(slot, sess, sc);
    return sess;
  }
  function kcPushLoop(slot, sess, sc) {
    sc.running = true;
    (async () => {
      let backoff = 2000;
      while (kcPushSessions[slot] === sess && !sess.closed) {
        const t0 = Date.now();
        try {
          const b = await kcBulletPrivate(sess.creds, sc.mk, sess.route);
          if (!b.ok) throw new Error(b.message || 'bullet refused');
          await kcPushConn(slot, sess, sc, b);
          if (Date.now() - t0 > 60000) backoff = 2000;   // productive conn resets
        } catch (e) {
          sess.err = 'KuCoin push: ' + ((e && e.message) || 'error');
          tdiag('acct', 'kucoin_push_err',
                { s: slot, mk: sc.mk, m: String(sess.err).slice(0, 120) });
        }
        kcPushScopeReset(sc);
        if (sess.closed || kcPushSessions[slot] !== sess) break;
        await krWsSleep(backoff);
        backoff = Math.min(backoff * 2, 60000);
      }
      sc.running = false;
    })().catch(() => { sc.running = false; });
  }
  // Signed bullet for ONE host. Validated through the SAME kcBulletParse the
  // public market-data bridge uses (wss-only + *.kucoin.com suffix): the
  // endpoint host varies per bullet, so that check is what keeps this from
  // becoming an arbitrary-socket primitive.
  async function kcBulletPrivate(creds, market, route) {
    const r = await kcRequest(creds, 'POST', market, '/api/v1/bullet-private',
                              null, null, route);
    if (!r.ok) return { ok: false, message: r.message || 'bullet-private failed' };
    const p = kcBulletParse(r.data);
    if (!p.ok) return { ok: false, message: 'bullet-private ' + (p.error || 'invalid') };
    return p;
  }
  function kcPushConn(slot, sess, sc, bullet) {
    return new Promise((resolve, reject) => {
      const ws = krWsDial(kcDialUrl(bullet.endpoint, bullet.token, kcPushNextId()),
                          sess.route);
      if (!ws) { reject(new Error('proxy agent unavailable')); return; }
      sc.ws = ws;
      let settled = false;
      let acked = 0;
      let expect = 0;
      const done = (err) => {
        if (settled) return;
        settled = true;
        clearInterval(kaT);
        sc.up = false;
        try { ws.terminate(); } catch (e) { /* closed */ }
        if (err) reject(err); else resolve();
      };
      // APP-LEVEL keepalive — a WS protocol ping does NOT hold this socket up.
      const kaT = setInterval(() => {
        try { ws.send(JSON.stringify({ id: kcPushNextId(), type: 'ping' })); }
        catch (e) { /* dying */ }
        if (Date.now() - (sc.lastMsg || 0) > KC_PUSH_STALL_MS) done(new Error('stream stalled'));
      }, bullet.pingMs || 16000);
      if (kaT && typeof kaT.unref === 'function') kaT.unref();
      const sub = (topic, essential) => {
        const id = kcPushNextId();
        sc.subT[id] = topic;
        if (essential) expect++;
        try {
          ws.send(JSON.stringify({ id: id, type: 'subscribe', topic: topic,
                                   privateChannel: true, response: true }));
        } catch (e) { done(e); }
      };
      sc.subs = sub;
      ws.on('open', () => {
        sc.lastMsg = Date.now();
        // per-CONNECTION seed state (bitget recipe): `fseen` makes the first
        // frame of a topic the subscribe snapshot; `connT` is the venue-clock
        // time at connect, so a replayed fill is told from a live one by its
        // OWN timestamp; `openT` is the LOCAL stamp the ack grace measures.
        sc.subT = {};
        sc.fseen = {};
        sc.connT = Date.now() + (sess.tOff || 0);
        sc.openT = Date.now();
        sc.fillCh = 0;
        sc.posSub = {};
      });
      ws.on('ping', () => { sc.lastMsg = Date.now(); });
      ws.on('message', (buf) => {
        sc.lastMsg = Date.now();
        let msg = null;
        try { msg = JSON.parse(buf.toString()); } catch (e) { return; }
        const ty = String((msg && msg.type) || '');
        if (ty === 'pong' || ty === 'ping') return;
        if (ty === 'welcome') {
          if (sc.mk === 'spot') {
            sub('/spotMarket/tradeOrdersV2', true);
            sub('/account/balance', true);
          } else {
            sub('/contractMarket/tradeOrders', true);
            sub('/contractAccount/wallet', true);
            // BONUS: untriggered stops never ride tradeOrders.
            sub('/contractMarket/advancedOrders', false);
            for (const s of Object.keys(sc.posWant || {})) kcPosSub(sc, s);
          }
          return;
        }
        if (ty === 'error') {
          const topic = String((sc.subT || {})[String((msg && msg.id) || '')] || '');
          // A refused BONUS topic must NOT tear the socket down: killing the
          // connection would take orders/fills/wallet with it and redial
          // forever for a channel that is additive by construction.
          if (topic && !kcTopicEssential(topic)) {
            if (topic === '/contractMarket/tradeOrders' || topic === '/spotMarket/tradeOrdersV2') {
              kcFillChSet(sc, -1);
            }
            tdiag('acct', 'kucoin_push_nosub',
                  { s: slot, mk: sc.mk, t: topic,
                    m: String((msg && msg.data) || '').slice(0, 80) });
            return;
          }
          if (kcTopicIsOrders(topic)) kcFillChSet(sc, -1);
          done(new Error('kucoin ws: ' + String((msg && msg.data) || 'error')));
          return;
        }
        if (ty === 'ack') {
          const topic = String((sc.subT || {})[String((msg && msg.id) || '')] || '');
          // An acked orders topic takes OWNERSHIP of this market's fill
          // EVENTS (see kcFillChSet) — the REST poll keeps recording them.
          if (kcTopicIsOrders(topic)) {
            kcFillChSet(sc, 1);
            tdiag('acct', 'kucoin_push_fillch', { s: slot, mk: sc.mk, st: sc.fillCh | 0 });
          }
          if (!kcTopicEssential(topic)) return;
          acked++;
          if (expect > 0 && acked >= expect && !sc.up) {
            sc.up = true; sess.err = null;
            tdiag('acct', 'kucoin_push_up', { s: slot, mk: sc.mk });
          }
          return;
        }
        if (ty !== 'message') return;
        try { kcPushEvApply(sess, sc, msg); } catch (e) { /* row skipped */ }
      });
      ws.on('error', (e) => done(e || new Error('ws error')));
      ws.on('close', () => done(new Error('closed')));
    });
  }
  function kcTopicIsOrders(topic) {
    return topic === '/contractMarket/tradeOrders' || topic === '/spotMarket/tradeOrdersV2';
  }
  function kcTopicEssential(topic) {
    return kcTopicIsOrders(topic) || topic === '/account/balance'
      || topic === '/contractAccount/wallet';
  }
  // Per-market, per-CONNECTION fill-EVENT ownership, monotone for the life of
  // one connection: pending(0) → owned(1) on an ack inside the grace, or →
  // fallback(-1) on a refusal or a grace that ran out, and NEVER back. A late
  // ack is demoted on purpose — the REST poll has already been emitting for
  // this market, and a stream that starts emitting alongside it would chime
  // executions the poll just chimed. The reconnect re-decides.
  function kcFillAckLate(sc) {
    return (Date.now() - ((sc && sc.openT) || 0)) >= KC_FILL_ACK_GRACE_MS;
  }
  function kcFillChSet(sc, st) {
    if (!sc) return 0;
    if (st > 0 && ((sc.fillCh | 0) < 0 || kcFillAckLate(sc))) st = -1;
    sc.fillCh = st;
    return st;
  }
  function kcFillLaneOwns(sc) {
    const st = (sc && sc.fillCh) | 0;
    if (st) return st > 0;
    if (!kcFillAckLate(sc)) return true;      // pending, inside the grace
    kcFillChSet(sc, -1);                      // …and the timeout LATCHES
    return false;
  }
  // A fill-BEARING row: a venue trade id plus a positive THIS-fill quantity.
  function kcFillQty(o) {
    const m = parseFloat(o && o.matchSize);
    if (Number.isFinite(m) && m > 0) return m;
    const s = parseFloat(o && o.size);
    return (Number.isFinite(s) && s > 0) ? s : 0;
  }
  function kcFillRow(o) {
    return !!(o && o.tradeId != null && String(o.tradeId) && kcFillQty(o) > 0);
  }
  // fid namespace = '<tradeId>:<side>' — byte-identical to the panel's
  // lbFill/state-fill eid, so ONE chime latch covers the pushed match delta,
  // its fee-enriched re-push and the same fill arriving on the next acct read.
  function kcFillFid(o) {
    return String((o && o.tradeId) || '') + ':' + String((o && o.side) || '').toLowerCase();
  }
  const KC_SHAPE_KEYS = ['tradeId', 'orderId', 'clientOid', 'symbol', 'side', 'type',
    'orderType', 'matchSize', 'matchPrice', 'size', 'price', 'filledSize', 'remainSize',
    'fee', 'feeCurrency', 'feeType', 'liquidity', 'status', 'ts', 'orderTime',
    'tradeTime', 'createdAt'];
  function kcPushShapeDiag(sc, topic, row) {
    if (!row || typeof row !== 'object') return;
    if (!sc.shape) sc.shape = {};
    if (sc.shape[topic]) return;
    sc.shape[topic] = 1;
    const have = [];
    for (const n of KC_SHAPE_KEYS) {
      const v = row[n];
      if (v !== undefined && v !== null && v !== '') have.push(n);
    }
    tdiag('acct', 'kucoin_push_shape', { s: sc._pk, t: topic, keys: have.join(',') });
  }
  // One EMITTED fill. The row is NOT written to the ring here: a match delta
  // has no fee, and an unknown fee must never be stored as a real zero — the
  // catch-up poll below records the same execution with the venue's own fee
  // and re-pushes the same fid, which the panel merges over this row.
  function kcWsMatch(sess, sc, o) {
    if (!kcFillRow(o)) return;
    kcPushShapeDiag(sc, 'match|' + sc.mk, o);
    if (!kcFillLaneOwns(sc)) { sc.lt++; return; }
    if (!lbKcFeeKnown(o)) sc.nf++;
    // Recorded by the poll either way; only the EVENT is age-gated, so a
    // subscribe replay can never chime historical fills.
    const ts = lbKcTsMs(o);
    if (!ts || ts >= ((sc.connT || 0) - KC_PUSH_FRESH_MS)) {
      // fid ONLY — no row. The panel's fee/break-even replay must never see
      // a fee-less delta (that is the "unknown fee stored as a real zero"
      // failure in another disguise); kcPushFillRows below re-pushes the SAME
      // fid carrying the recorded, fee-bearing row a few hundred ms later.
      krLseq(sc); kcPushSc(sc, 'fill', kcFillFid(o));
      if (sc.mk === 'futures') { krLseq(sc); kcPushSc(sc, 'pos'); }
    }
    kcFillCatchUp(sess, sc.mk);
  }
  // Debounced, single-flight REST catch-up: the fee-and-realized-PnL half of
  // the lane. Best-effort — a failed catch-up just means the fill records on
  // the next lblot beat, never a zero-fee row.
  function kcFillCatchUp(sess, mk) {
    if (!sess || sess.closed) return;
    if (!sess.cu) sess.cu = {};
    if (sess.cu[mk]) return;
    sess.cu[mk] = setTimeout(() => {
      sess.cu[mk] = null;
      lbKcLive('kucoin', sess.slot, sess.route, mk)
        .catch(() => { /* next beat retries */ });
    }, KC_PUSH_CATCHUP_MS);
    if (sess.cu[mk] && typeof sess.cu[mk].unref === 'function') sess.cu[mk].unref();
  }
  // Per-symbol futures position subscription (KuCoin has no all-symbols
  // channel). Bounded: the cap protects a many-symbol account from turning
  // one reconnect into dozens of frames.
  function kcPosSub(sc, symbol) {
    const s = String(symbol || '');
    if (!s || !sc || sc.mk !== 'futures') return;
    if (sc.posSub && sc.posSub[s]) return;
    if (Object.keys(sc.posSub || {}).length >= KC_PUSH_POS_CAP) return;
    if (!sc.ws || !sc.subT || typeof sc.subs !== 'function') return;
    sc.posSub[s] = 1;
    sc.subs('/contract/position:' + s, false);
  }
  // Symbols the account is known to hold — seeded by the acct read so the
  // position row is push-driven from the first beat, not from the first fill.
  function kcPushPosWatch(slot, symbols) {
    const sess = kcPushSessions[String(slot || 'kucoin')];
    if (!sess) return;
    const sc = sess.fu;
    for (const s0 of (symbols || [])) {
      const s = String(s0 || '');
      if (!s) continue;
      if (!sc.posWant) sc.posWant = {};
      if (Object.keys(sc.posWant).length < KC_PUSH_POS_CAP) sc.posWant[s] = 1;
      kcPosSub(sc, s);
    }
  }
  function kcPushEvApply(sess, sc, msg) {
    const topic = String((msg && msg.topic) || '');
    const data = (msg && msg.data) || {};
    if (!topic) return;
    if (!sc.fseen) sc.fseen = {};
    const base = topic.indexOf(':') >= 0 ? topic.slice(0, topic.indexOf(':')) : topic;
    const snap = !sc.fseen[topic];
    sc.fseen[topic] = 1;
    if (kcTopicIsOrders(topic)) {
      const ev = String(data.type || '');
      const oid = String(data.orderId || '');
      if (ev === 'match') {
        if (sc.mk === 'futures' && data.symbol) kcPosSub(sc, String(data.symbol));
        kcWsMatch(sess, sc, data);
      }
      if (!oid) return;
      // engine kc_*_ws_apply parity: filled/canceled (or futures status
      // 'done') retire the badge; open/update/match keep it.
      const done = ev === 'filled' || ev === 'canceled'
        || String(data.status || '') === 'done';
      if (done) { krLseq(sc); kcPushSc(sc, 'ordgone', oid); return; }
      if (KC_PUSH_OPEN_EV[ev] && !snap) { krLseq(sc); kcPushSc(sc, 'order', null, data); }
      return;
    }
    if (topic === '/contractMarket/advancedOrders') {
      // Untriggered STOP orders. `type`: open / triggered / cancel. The ids
      // are 'st:'-namespaced exactly like the REST /api/v1/stopOrders rows,
      // so a push retirement clears the same badge the poll would.
      const oid = String(data.orderId || '');
      if (!oid) return;
      const ev = String(data.type || '');
      if (ev === 'open') { krLseq(sc); kcPushSc(sc, 'order', null, kcStopEvRow(data)); }
      else { krLseq(sc); kcPushSc(sc, 'ordgone', 'st:' + oid); }
      return;
    }
    if (base === '/contract/position') {
      // Venue-truth position rows. A flat row (currentQty 0) is pushed too —
      // the panel retires the posrow (and sweeps its reduce-only stops) on
      // THIS beat instead of waiting for a poll to notice the absence.
      const sym = String(data.symbol || topic.slice(base.length + 1) || '');
      if (!sym) return;
      // A `position.change` frame with changeReason 'markPriceChange' carries
      // ONLY the new mark — no currentQty. Read as a position row that would
      // be a FLAT row and would retire a live posrow on every mark tick, so a
      // frame without the quantity is not a position frame at all here.
      if (data.currentQty === undefined || data.currentQty === null) return;
      const row = Object.assign({}, data, { symbol: sym });
      if (!sc.posSyms) sc.posSyms = {};
      sc.posSyms[sym] = 1;
      krLseq(sc); kcPushSc(sc, 'pos', null, row);
      return;
    }
    if ((topic === '/account/balance' || topic === '/contractAccount/wallet') && !snap) {
      krLseq(sc); kcPushSc(sc, 'bal', null, data);
    }
  }
  // advancedOrders frames name the trigger side as `stop` ('up'/'down') on
  // some builds and omit it on others. Missing direction stays MISSING (the
  // panel then falls back to its side-derived family) rather than guessing —
  // a wrong guess paints the chip the wrong colour until the next reconcile.
  function kcStopEvRow(d) {
    const r = {
      id: String(d.orderId || ''), symbol: String(d.symbol || ''),
      side: String(d.side || ''), type: String(d.orderType || d.orderPrice ? 'limit' : 'market'),
      stopPrice: d.stopPrice != null ? String(d.stopPrice) : '',
      size: d.size != null ? String(d.size) : '',
      createdAt: d.createdAt != null ? d.createdAt : d.ts,
    };
    if (d.stop === 'up' || d.stop === 'down') r.stop = d.stop;
    return r;
  }
  // Optimistic mutation stamp at the order-send/cancel ack sites (Kraken/
  // Binance/Bybit/Gate/Bitget pattern): the WS echo lands ~100ms later, but
  // the local bump makes the badge/posrow read fire immediately after the
  // REST ack. `row` lets a freshly placed STOP carry its trigger direction so
  // the chip renders the right family at once instead of flickering to the
  // wrong colour until the next reconcile. Market-scoped: KuCoin order id
  // spaces are per-market (two hosts).
  function kcMutKick(slot, kind, oid, market, row) {
    const sess = kcPushSessions[String(slot || 'kucoin')];
    if (!sess) return;
    const sc = market === 'spot' ? sess.sp : sess.fu;
    if (kind === 'ordgone' && oid) {
      krLseq(sc); kcPushSc(sc, 'ordgone', String(oid));
    } else {
      krLseq(sc); kcPushSc(sc, 'order', null, row || undefined);
    }
  }

  // --- KuCoin ----------------------------------------------------------------
  // #2272 per-KEY + per-SYMBOL futures leverage memory — engine _kc_leverage
  // twin. KuCoin one-way cross has NO dependable persistent set-leverage
  // (`leverage` rides EACH order), so this memory is authoritative and the
  // cross-leverage endpoint is only a best-effort sync so the KuCoin web UI
  // agrees. KC_NATIVE_LEVERAGE is the fallback for a symbol never set here,
  // never a value silently pinned into every order.
  const KC_NATIVE_LEVERAGE = '10';   // engine KC_DEFAULT_LEVERAGE parity
  const kcLevMem = {};
  function kcLevKey(creds, symbol) { return String((creds && creds.key) || '') + '\u0000' + String(symbol || ''); }
  function kcLevFor(creds, symbol) {
    const v = kcLevMem[kcLevKey(creds, symbol)];
    return v != null && String(v) ? String(v) : KC_NATIVE_LEVERAGE;
  }
  const kcMultCache = {};

  async function kcRequest(creds, method, market, path, params, body, route) {
    const host = market === 'futures' ? KUCOIN_FUT_HOST : KUCOIN_SPOT_HOST;
    const q = params && params.length ? formEnc(params) : '';
    const bodyStr = body != null ? canonJson(body) : '';
    const reqPath = path + (q ? '?' + q : '');
    const ts = venueStampMs(await ensureVenueTime('kucoin', market, route));
    const headers = {
      'KC-API-KEY': creds.key,
      'KC-API-SIGN': kcSign(creds.secret, ts, method, reqPath, bodyStr),
      'KC-API-TIMESTAMP': ts,
      'KC-API-PASSPHRASE': kcPassphraseSig(creds.secret, String(creds.pass || '')),
      'KC-API-KEY-VERSION': '2',
    };
    let r;
    try {
      r = await httpJson(host, method, path, q, bodyStr || null, headers, route);
    } catch (e) { return transportFail(e, 'KuCoin'); }
    if (r.status === 429) {
      return { ok: false, message: 'Rate limited by KuCoin — retry shortly', status: 429 };
    }
    let data;
    try { data = r.text ? JSON.parse(r.text) : {}; } catch (e) {
      // Bare HTTP failures (e.g. an empty-body 404 on a stop delete) carry
      // the status so call sites can match "gone" without string games.
      return { ok: false, message: 'KuCoin returned HTTP ' + r.status, status: r.status };
    }
    const code = (data && typeof data === 'object' && data.code != null) ? String(data.code) : null;
    if (code == null) {
      if (r.status >= 400) {
        return { ok: false, message: 'KuCoin returned HTTP ' + r.status, status: r.status };
      }
      return { ok: true, data: data };
    }
    if (code === '200000') return { ok: true, data: data };
    return { ok: false, message: kcErrorMessage(code, String((data && data.msg) || '')),
             status: r.status };
  }

  // KuCoin rate-limit discipline for multi-call sweeps: space the calls and
  // give ONE mid-sweep 429 a breather + single retry instead of failing the
  // whole cancel-all (the unspaced sweep itself used to trip the limiter).
  const KC_SWEEP_SPACING_MS = 150;
  const KC_SWEEP_429_WAIT_MS = 1500;
  function kcRateLimited(rc) {
    return !rc.ok && (rc.status === 429 ||
                      String(rc.message || '').toLowerCase().indexOf('rate limited') >= 0);
  }
  function kcCancelGoneRc(rc) {
    return rc.status === 404 || kucoinCancelGone(rc.message);
  }

  async function kcMult(symbol, route) {
    const c = kcMultCache[symbol];
    if (c && Date.now() - c.ts < PRODUCTS_TTL_MS) return c.v;
    try {
      const r = await httpJson(KUCOIN_FUT_HOST, 'GET',
                               '/api/v1/contracts/' + encodeURIComponent(String(symbol)),
                               '', null, {}, route);
      const d = JSON.parse(r.text);
      const v = bnNum((((d || {}).data) || {}).multiplier) || null;
      if (v != null) kcMultCache[symbol] = { ts: Date.now(), v: v };
      return v;
    } catch (e) { return null; }
  }

  async function kcMarkPrice(symbol, route) {
    try {
      const r = await httpJson(KUCOIN_FUT_HOST, 'GET',
                               '/api/v1/mark-price/' + encodeURIComponent(String(symbol)) + '/current',
                               '', null, {}, route);
      const d = JSON.parse(r.text);
      return bnNum((((d || {}).data) || {}).value);
    } catch (e) { return null; }
  }

  async function execKucoin(creds, intent, route) {
    if (!creds.pass) return { ok: false, message: 'KuCoin API passphrase missing — re-provision Native trading on this device' };
    const market = intent.market === 'spot' ? 'spot' : 'futures';
    const fetchPos = async () => {
      const r = await kcRequest(creds, 'GET', 'futures', '/api/v1/positions', null, null, route);
      if (!r.ok) return r;
      const multMap = {};
      multMap[String(intent.symbol)] = await kcMult(intent.symbol, route);
      return { ok: true, rows: kcPositionRows(r.data, multMap) };
    };
    async function place(mkt, symbol, side, ordType, qty, price, clOrdID, flags) {
      const f = flags || {};
      const t = String(ordType).toLowerCase();
      const isStop = t === 'stop' || t === 'stop_limit' || t === 'tp_market';
      if (mkt !== 'futures') {
        if (isStop) return { ok: false, message: 'Stop orders are futures-only' };
        const body = kcSpotOrderBody(symbol, side, ordType, qty, price, clOrdID);
        const r = await kcRequest(creds, 'POST', 'spot', '/api/v1/orders', null, body, route);
        if (!r.ok) return r;
        const oid = String((((r.data || {}).data) || {}).orderId || '');
        return { ok: true, orderID: oid || null, clOrdID: clOrdID };
      }
      const mult = await kcMult(symbol, route);
      const contracts = kcContracts(qty, mult);
      if (!(Number(contracts) > 0)) {
        return { ok: false, message: 'Quantity below one contract (' + (kcBaseQty('1', mult) || '1') + ' minimum)' };
      }
      let trigDir = null;
      if (isStop) {
        const mark = await kcMarkPrice(symbol, route);
        trigDir = kcStopDir(side, f.trigger, mark);
      }
      const body = kcFutOrderBody(symbol, side, ordType, contracts, price, clOrdID,
                                  kcLevFor(creds, symbol),
                                  { reduceOnly: !!f.reduceOnly,
                                    trigger: isStop ? f.trigger : null,
                                    triggerDir: trigDir });
      const r = await kcRequest(creds, 'POST', 'futures', '/api/v1/orders', null, body, route);
      if (!r.ok) return r;
      const oid = String((((r.data || {}).data) || {}).orderId || '');
      if (isStop) {
        // #2272 the freshly placed chip carries its TRIGGER DIRECTION: the
        // stop-versus-target family is direction × side (KuCoin has no native
        // take-profit order type), and without it the chip flickers to the
        // wrong colour until the next reconcile.
        return { ok: true, orderID: oid ? 'st:' + oid : null, clOrdID: clOrdID,
                 kcStop: oid ? { id: oid, symbol: String(symbol), side: side,
                                 type: (t === 'limit' || t === 'stop_limit') ? 'limit' : 'market',
                                 stop: trigDir, stopPrice: String(f.trigger),
                                 size: String(contracts), createdAt: Date.now() } : null };
      }
      return { ok: true, orderID: oid || null, clOrdID: clOrdID };
    }
    if (intent.op === 'order') {
      return place(market, intent.symbol, intent.side, intent.type,
                   intent.qty, intent.price, intent.clOrdID,
                   { reduceOnly: !!intent.reduceOnly, trigger: intent.trigger });
    }
    if (intent.op === 'cancel') {
      const oid = String(intent.orderID);
      if (oid.indexOf('st:') === 0) {
        const r = await kcRequest(creds, 'DELETE', 'futures',
                                  '/api/v1/stopOrders/' + oid.slice(3), null, null, route);
        if (!r.ok) {
          // Older deployments cancel untriggered stops via the plain
          // endpoint — fall through before failing (engine parity).
          const r2 = await kcRequest(creds, 'DELETE', 'futures',
                                     '/api/v1/orders/' + oid.slice(3), null, null, route);
          if (!r2.ok) return r;
        }
        return { ok: true, cancelled: intent.orderID };
      }
      const r = await kcRequest(creds, 'DELETE', market, '/api/v1/orders/' + oid, null, null, route);
      if (!r.ok) return r;
      return { ok: true, cancelled: intent.orderID };
    }
    if (intent.op === 'cancel_all') {
      const r = await kcRequest(creds, 'DELETE', market, '/api/v1/orders',
                                [['symbol', String(intent.symbol)]], null, route);
      if (!r.ok) return r;
      if (market === 'futures') {
        // Clear untriggered stops too — terminal rule. ONE documented bulk
        // call (DELETE /api/v1/stopOrders?symbol=) replaces the old
        // 10-page-list + per-stop-delete sweep that tripped the rate limit;
        // the paced sweep survives only as a fallback.
        await sleepMs(KC_SWEEP_SPACING_MS);
        let rb = await kcRequest(creds, 'DELETE', 'futures', '/api/v1/stopOrders',
                                 [['symbol', String(intent.symbol)]], null, route);
        if (kcRateLimited(rb)) {
          await sleepMs(KC_SWEEP_429_WAIT_MS);
          rb = await kcRequest(creds, 'DELETE', 'futures', '/api/v1/stopOrders',
                               [['symbol', String(intent.symbol)]], null, route);
        }
        if (rb.ok || kcCancelGoneRc(rb)) return { ok: true, cancelled: 'all' };
        // Fallback: paced per-stop sweep (spacing + one mid-sweep 429 retry).
        const pend = [];
        for (let page = 1; page <= 10; page++) {
          await sleepMs(KC_SWEEP_SPACING_MS);
          const rp = await kcRequest(creds, 'GET', 'futures', '/api/v1/stopOrders',
                                     [['currentPage', String(page)], ['pageSize', '100']],
                                     null, route);
          if (!rp.ok) return rp;
          const d = ((rp.data || {}).data) || {};
          const lst = Array.isArray(d.items) ? d.items : [];
          for (const o of lst) {
            if (String((o || {}).symbol || '') !== String(intent.symbol)) continue;
            const sid = String(o.id || '');
            if (sid) pend.push(sid);
          }
          let total = parseInt(d.totalPage, 10);
          if (!isFinite(total)) total = 1;
          if (page >= total || !lst.length) break;
        }
        for (const sid of pend) {
          await sleepMs(KC_SWEEP_SPACING_MS);
          let rc = await kcRequest(creds, 'DELETE', 'futures',
                                   '/api/v1/stopOrders/' + sid, null, null, route);
          if (kcRateLimited(rc)) {
            await sleepMs(KC_SWEEP_429_WAIT_MS);
            rc = await kcRequest(creds, 'DELETE', 'futures',
                                 '/api/v1/stopOrders/' + sid, null, null, route);
          }
          if (!rc.ok) {
            if (kcCancelGoneRc(rc)) continue;
            return rc;
          }
        }
      }
      return { ok: true, cancelled: 'all' };
    }
    const pr = await findPosRetry(fetchPos, intent.symbol);
    if (!pr.ok) return pr;
    if (intent.op === 'close') {
      if (!pr.pos) return { ok: false, message: 'Position not found' };
      const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
      const r = await place('futures', pr.pos.symbol, side, 'market', pr.pos.size,
                            null, intent.clOrdID, { reduceOnly: true });
      if (!r.ok) return r;
      return { ok: true, orderID: r.orderID, clOrdID: intent.clOrdID };
    }
    if (!pr.pos) return { ok: false, message: 'No open position to protect' };
    const terr = sltpTriggerOk(intent.kind, pr.pos.side, intent.trigger, pr.pos.mark);
    if (terr) return { ok: false, message: terr };
    const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
    const ordType = intent.kind === 'sl' ? 'stop' : 'tp_market';
    const r = await place('futures', pr.pos.symbol, side, ordType, pr.pos.size,
                          null, intent.clOrdID,
                          { reduceOnly: true, trigger: intent.trigger });
    if (!r.ok) return r;
    return { ok: true, kind: intent.kind, orderID: r.orderID, clOrdID: intent.clOrdID };
  }

  // --- BitMEX ----------------------------------------------------------------
  const bmxInstCache = {};

  async function bmxRequest(creds, method, path, params, bodyStr, route) {
    const q = params && params.length ? formEnc(params) : '';
    const reqPath = BITMEX_API_PREFIX + path + (q ? '?' + q : '');
    const expires = bmxExpires((Date.now() + await ensureVenueTime('bitmex', null, route)) / 1000);
    const headers = {
      'api-key': creds.key,
      'api-expires': String(expires),
      'api-signature': bmxSign(creds.secret, method, reqPath, expires, bodyStr || ''),
    };
    let r;
    try {
      r = await httpJson(BITMEX_HOST, method, BITMEX_API_PREFIX + path, q,
                         bodyStr || null, headers, route);
    } catch (e) { return transportFail(e, 'BitMEX'); }
    if (r.status === 429) {
      // #1724: BitMEX ships an honest Retry-After (seconds) — hand it to the
      // acct_read guard as an explicit venue cool-down hint.
      const ras = Number(r.ra);
      return { ok: false, rateLimited: true, message: 'Rate limited by BitMEX — retry shortly',
               retryInMs: (Number.isFinite(ras) && ras > 0) ? Math.min(ras * 1000, ACCT_RL_MAX_MS) : null };
    }
    let data;
    try { data = r.text ? JSON.parse(r.text) : {}; } catch (e) {
      return { ok: false, message: 'BitMEX returned HTTP ' + r.status };
    }
    if (r.status >= 400) {
      let msg = '';
      if (data && data.error && typeof data.error === 'object') msg = String(data.error.message || '');
      return { ok: false, message: msg || ('BitMEX returned HTTP ' + r.status) };
    }
    return { ok: true, data: data };
  }

  async function bmxInstrument(symbol, route) {
    const c = bmxInstCache[symbol];
    if (c && Date.now() - c.ts < PRODUCTS_TTL_MS) return c.v;
    try {
      const r = await httpJson(BITMEX_HOST, 'GET', BITMEX_API_PREFIX + '/instrument',
                               formEnc([['symbol', String(symbol)], ['count', '1']]),
                               null, {}, route);
      const d = JSON.parse(r.text);
      const row = (Array.isArray(d) && d[0]) || {};
      const v = { u2pm: bnNum(row.underlyingToPositionMultiplier), lot: bnNum(row.lotSize) };
      if (v.u2pm != null) bmxInstCache[symbol] = { ts: Date.now(), v: v };
      return v;
    } catch (e) { return null; }
  }

  async function bmxLastPrice(symbol, route) {
    // Uncached — live sizing for spot market buys.
    try {
      const r = await httpJson(BITMEX_HOST, 'GET', BITMEX_API_PREFIX + '/instrument',
                               formEnc([['symbol', String(symbol)], ['count', '1']]),
                               null, {}, route);
      const d = JSON.parse(r.text);
      return bnNum(((Array.isArray(d) && d[0]) || {}).lastPrice);
    } catch (e) { return null; }
  }

  async function execBitmex(creds, intent, route) {
    const market = intent.market === 'spot' ? 'spot' : 'futures';
    const fetchPos = async () => {
      const r = await bmxRequest(creds, 'GET', '/position',
                                 [['filter', '{"isOpen":true}'], ['count', '500']],
                                 null, route);
      if (!r.ok) return r;
      const spec = await bmxInstrument(intent.symbol, route);
      const multMap = {};
      multMap[String(intent.symbol)] = spec && spec.u2pm;
      return { ok: true, rows: bmxPositionRows(r.data, multMap) };
    };
    async function place(mkt, symbol, side, ordType, qty, price, clOrdID, flags) {
      const f = flags || {};
      const t = String(ordType).toLowerCase();
      const isStop = t === 'stop' || t === 'stop_limit' || t === 'tp_market';
      if (mkt === 'spot' && isStop) return { ok: false, message: 'Stop orders are futures-only' };
      const spec = await bmxInstrument(symbol, route);
      if (!spec || !spec.u2pm) return { ok: false, message: 'Unknown BitMEX symbol ' + symbol };
      let qtyBase = String(qty);
      if (mkt === 'spot' && t === 'market' && String(side).toLowerCase() === 'buy') {
        const px = await bmxLastPrice(symbol, route);
        if (!px || !(Number(px) > 0)) return { ok: false, message: 'No live price to size the market buy' };
        const qb = Number(qty) / Number(px);
        if (!isFinite(qb) || !(qb > 0)) return { ok: false, message: 'Invalid quantity' };
        qtyBase = bnNum(qb.toFixed(12)) || String(qb);
      }
      const contracts = bmxContracts(qtyBase, spec.u2pm, spec.lot);
      if (!(Number(contracts) > 0)) {
        return { ok: false, message: 'Quantity below one lot (' +
          (bmxBaseQty(spec.lot, spec.u2pm) || spec.lot || '1') + ' minimum)' };
      }
      let bodyStr;
      try {
        bodyStr = bmxOrderBody(symbol, side, ordType, contracts, price, clOrdID,
                               { reduceOnly: !!f.reduceOnly, trigger: f.trigger,
                                 closeOnTrigger: !!f.closeOnTrigger });
      } catch (e) {
        return { ok: false, message: (e && e.message) || 'bad order' };
      }
      const r = await bmxRequest(creds, 'POST', '/order', null, bodyStr, route);
      if (!r.ok) return r;
      const oid = String((r.data || {}).orderID || '');
      return { ok: true, orderID: oid || null, clOrdID: clOrdID };
    }
    if (intent.op === 'order') {
      return place(market, intent.symbol, intent.side, intent.type,
                   intent.qty, intent.price, intent.clOrdID,
                   { reduceOnly: !!intent.reduceOnly, trigger: intent.trigger });
    }
    if (intent.op === 'cancel') {
      const r = await bmxRequest(creds, 'DELETE', '/order',
                                 [['orderID', String(intent.orderID)]], null, route);
      if (!r.ok) {
        if (bitmexCancelGone(r.message)) return { ok: true, cancelled: intent.orderID };
        return r;
      }
      // 200-with-row-error scan (BitMEX reports per-row cancel failures).
      for (const row of (Array.isArray(r.data) ? r.data : [])) {
        const err = String((row || {}).error || '');
        if (err && !bitmexCancelGone(err)) return { ok: false, message: err };
      }
      return { ok: true, cancelled: intent.orderID };
    }
    if (intent.op === 'cancel_all') {
      const r = await bmxRequest(creds, 'DELETE', '/order/all',
                                 [['symbol', String(intent.symbol)]], null, route);
      if (!r.ok) return r;
      return { ok: true, cancelled: 'all' };
    }
    const pr = await findPosRetry(fetchPos, intent.symbol);
    if (!pr.ok) return pr;
    if (intent.op === 'close') {
      if (!pr.pos) return { ok: false, message: 'Position not found' };
      const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
      const r = await place('futures', pr.pos.symbol, side, 'market', pr.pos.size,
                            null, intent.clOrdID, { reduceOnly: true });
      if (!r.ok) return r;
      return { ok: true, orderID: r.orderID, clOrdID: intent.clOrdID };
    }
    if (!pr.pos) return { ok: false, message: 'No open position to protect' };
    const terr = sltpTriggerOk(intent.kind, pr.pos.side, intent.trigger, pr.pos.mark);
    if (terr) return { ok: false, message: terr };
    const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
    const ordType = intent.kind === 'sl' ? 'stop' : 'tp_market';
    const r = await place('futures', pr.pos.symbol, side, ordType, pr.pos.size,
                          null, intent.clOrdID,
                          { reduceOnly: true, trigger: intent.trigger });
    if (!r.ok) return r;
    return { ok: true, kind: intent.kind, orderID: r.orderID, clOrdID: intent.clOrdID };
  }

  // --- MEXC --------------------------------------------------------------------
  const mxCtCache = {};
  // Per-session accepted spot qty scale by symbol (engine _mx_spot_scale
  // parity): filled by the trim-retry below, pre-floors later orders.
  const mxSpotScaleMemo = {};

  async function mxRequest(creds, method, market, path, params, body, route) {
    const plist = (params || []).slice();
    let headers = {};
    let bodyStr = null;
    let host, query;
    if (market === 'futures') {
      host = MEXC_FUT_HOST;
      query = formEnc(plist);
      if (body != null) {
        bodyStr = JSON.stringify(body);           // separators(',',':') parity
        headers['Content-Type'] = 'application/json';
      }
      const ts = venueStampMs(await ensureVenueTime('mexc', 'futures', route));
      let paramStr;
      if (body != null) paramStr = bodyStr;
      else {
        const pd = {};
        for (const kv of plist) pd[String(kv[0])] = String(kv[1]);
        paramStr = mexcFutParamStr(pd);
      }
      headers['ApiKey'] = creds.key;
      headers['Request-Time'] = ts;
      headers['Signature'] = mexcFutSign(creds.key, creds.secret, ts, paramStr);
    } else {
      host = MEXC_SPOT_HOST;
      plist.push(['recvWindow', '10000']);
      plist.push(['timestamp', venueStampMs(await ensureVenueTime('mexc', 'spot', route))]);
      query = formEnc(plist);
      query += '&signature=' + mexcSpotSign(creds.secret, query);
      headers['X-MEXC-APIKEY'] = creds.key;
    }
    let r;
    try {
      r = await httpJson(host, method, path, query, bodyStr, headers, route);
    } catch (e) { return transportFail(e, 'MEXC'); }
    if (r.status === 429) return { ok: false, message: 'Rate limited by MEXC — retry shortly' };
    let data;
    try { data = r.text ? JSON.parse(r.text) : {}; } catch (e) {
      return { ok: false, message: 'MEXC returned HTTP ' + r.status };
    }
    if (market === 'futures') {
      if (data && typeof data === 'object' && 'success' in data) {
        if (data.success) return { ok: true, data: data };
        const code = parseInt(data.code, 10);
        return { ok: false, code: isFinite(code) ? code : -1,
                 message: mexcErrorMessage(data.code, String(data.message || data.msg || '')) };
      }
      if (r.status >= 400) return { ok: false, message: 'MEXC returned HTTP ' + r.status };
      return { ok: true, data: data };
    }
    // spot: flat payloads; errors carry {code, msg}
    if (data && typeof data === 'object' && data.code != null && data.msg != null
        && !('symbol' in data) && !('orderId' in data)) {
      const code = parseInt(data.code, 10);
      const c = isFinite(code) ? code : -1;
      if (c !== 200 && (r.status >= 400 || c !== 0)) {
        return { ok: false, code: c, message: mexcErrorMessage(data.code, String(data.msg || '')) };
      }
    }
    if (r.status >= 400) {
      if (data && typeof data === 'object' && data.code != null) {
        return { ok: false, message: mexcErrorMessage(data.code, String(data.msg || '')) };
      }
      return { ok: false, message: 'MEXC returned HTTP ' + r.status };
    }
    return { ok: true, data: data };
  }

  // Public futures contract detail → { cv: contractSize, vs: volUnit } (TTL).
  async function mxCt(symbol, route) {
    const c = mxCtCache[symbol];
    if (c && Date.now() - c.ts < PRODUCTS_TTL_MS) return c.v;
    try {
      const r = await httpJson(MEXC_FUT_HOST, 'GET', '/api/v1/contract/detail',
                               formEnc([['symbol', String(symbol)]]), null, {}, route);
      const d = JSON.parse(r.text);
      let row = (d || {}).data;
      if (Array.isArray(row)) row = row[0];
      row = row || {};
      const v = { cv: bnNum(row.contractSize), vs: bnNum(row.volUnit) || '1' };
      if (v.cv != null) mxCtCache[symbol] = { ts: Date.now(), v: v };
      return v;
    } catch (e) { return { cv: null, vs: null }; }
  }

  async function execMexc(creds, intent, route) {
    const market = intent.market === 'spot' ? 'spot' : 'futures';
    const fetchPos = async () => {
      const r = await mxRequest(creds, 'GET', 'futures',
                                '/api/v1/private/position/open_positions', null, null, route);
      if (!r.ok) return r;
      const spec = await mxCt(intent.symbol, route);
      return { ok: true, rows: mexcPositionRows(r.data, spec.cv) };
    };
    async function place(mkt, symbol, side, ordType, qty, price, clOrdID, flags) {
      const f = flags || {};
      const t = String(ordType).toLowerCase();
      const isStop = t === 'stop' || t === 'stop_limit' || t === 'tp_market';
      if (mkt !== 'futures') {
        if (isStop) return { ok: false, message: 'Stop orders are futures-only' };
        // BASE-quantity shapes only (market BUY sends quoteOrderQty = USDT):
        // pre-floor to any per-symbol scale MEXC previously accepted this
        // session (engine _mx_spot_scale recipe).
        const sendsBase = !(t !== 'limit' && String(side).toLowerCase() === 'buy');
        let sendQty = String(qty);
        if (sendsBase) {
          const memo = mxSpotScaleMemo[symbol];
          if (memo != null && mexcQtyScale(sendQty) > memo) {
            const q3 = mexcQtyFloorScale(sendQty, memo);
            if (q3 != null && Number(q3) > 0) sendQty = q3;
          }
        }
        let params = mexcSpotOrderParams(symbol, side, ordType, sendQty, price, clOrdID);
        let r = await mxRequest(creds, 'POST', 'spot', '/api/v3/order', params, null, route);
        if (!r.ok && sendsBase && mexcIsQtyScaleErr(r.message || r.data)) {
          // Bounded trim-one-decimal retry: MEXC's accepted scale for this
          // symbol is coarser than everything published — floor a decimal
          // off at a time (never up) until it takes or the quantity dies.
          // Accepted scale memoized per symbol for the session (engine
          // trim-retry parity, terminal_engine mexc spot place).
          let sc = mexcQtyScale(sendQty);
          for (let att = 0; att < 6 && !r.ok && sc > 0; att++) {
            sc -= 1;
            const nq = mexcQtyFloorScale(sendQty, sc);
            if (nq == null || !(Number(nq) > 0)) break;
            params = mexcSpotOrderParams(symbol, side, ordType, nq, price, clOrdID);
            r = await mxRequest(creds, 'POST', 'spot', '/api/v3/order', params, null, route);
            if (r.ok) { mxSpotScaleMemo[symbol] = sc; break; }
            if (!mexcIsQtyScaleErr(r.message || r.data)) break;
          }
        }
        if (!r.ok) {
          // API-restricted symbol (10007): the engine's UID/web-session
          // bypass is a SERVER-side path — native cannot ride it. Honest
          // guidance instead of a silent retry.
          if (mexcIsRestrictedErr(r.code)) {
            return { ok: false, message: mexcErrorMessage(10007) +
              ' — or switch Trading to Server for this symbol (the web-session bypass is server-only)' };
          }
          return r;
        }
        const oid = String((r.data || {}).orderId || '');
        return { ok: true, orderID: oid || null, clOrdID: mexcClOrdId(clOrdID) };
      }
      const spec = await mxCt(symbol, route);
      const contracts = mexcContracts(qty, spec.cv, spec.vs);
      if (!(Number(contracts) > 0)) {
        return { ok: false, message: 'Quantity below one contract (' +
          (mexcBaseQty(spec.vs || '1', spec.cv) || '1') + ' minimum)' };
      }
      if (isStop) {
        // SL/TP (reduce-only) trigger vs FAIR/mark — terminal-stop-orders
        // rule; entry stops watch last price (engine parity).
        const body = mexcPlanBody(symbol, side, t, contracts, price, f.trigger,
                                  { leverage: MX_NATIVE_LEVERAGE,
                                    reduceOnly: !!f.reduceOnly,
                                    triggerType: f.reduceOnly ? 2 : 1 });
        const r = await mxRequest(creds, 'POST', 'futures',
                                  '/api/v1/private/planorder/place', null, body, route);
        if (!r.ok) return r;
        const oid = String((r.data || {}).data || '');
        return { ok: true, orderID: oid ? 'mx:' + oid : null, clOrdID: clOrdID };
      }
      const body = mexcFutOrderBody(symbol, side, ordType, contracts, price, clOrdID,
                                    { leverage: MX_NATIVE_LEVERAGE,
                                      reduceOnly: !!f.reduceOnly });
      const r = await mxRequest(creds, 'POST', 'futures',
                                '/api/v1/private/order/submit', null, body, route);
      if (!r.ok) return r;
      const d = (r.data || {}).data;
      const oid = String((d && typeof d === 'object') ? (d.orderId || '') : (d || ''));
      return { ok: true, orderID: oid || null, clOrdID: mexcClOrdId(clOrdID) };
    }
    if (intent.op === 'order') {
      return place(market, intent.symbol, intent.side, intent.type,
                   intent.qty, intent.price, intent.clOrdID,
                   { reduceOnly: !!intent.reduceOnly, trigger: intent.trigger });
    }
    if (intent.op === 'cancel') {
      const oid = String(intent.orderID);
      if (oid.indexOf('mxw:') === 0) {
        // Restricted-spot web orders live on the server's web-session path.
        return { ok: false, message: 'This order was placed through the MEXC web session — ' +
                 'switch Trading to Server to cancel it' };
      }
      if (oid.indexOf('mx:') === 0) {
        const r = await mxRequest(creds, 'POST', 'futures', '/api/v1/private/planorder/cancel',
                                  null, [{ symbol: String(intent.symbol), orderId: oid.slice(3) }],
                                  route);
        if (!r.ok) return r;
        return { ok: true, cancelled: intent.orderID };
      }
      if (market === 'futures') {
        const r = await mxRequest(creds, 'POST', 'futures', '/api/v1/private/order/cancel',
                                  null, [oid], route);
        if (!r.ok) return r;
        // per-id result rides data rows: [{orderId, errorCode, errorMsg}]
        for (const row of ((r.data || {}).data || [])) {
          if (String((row || {}).orderId) === oid && parseInt(row.errorCode || 0, 10) !== 0) {
            return { ok: false, message: mexcErrorMessage(row.errorCode, String(row.errorMsg || '')) };
          }
        }
        return { ok: true, cancelled: intent.orderID };
      }
      const r = await mxRequest(creds, 'DELETE', 'spot', '/api/v3/order',
                                [['symbol', String(intent.symbol)], ['orderId', oid]], null, route);
      if (!r.ok) return r;
      return { ok: true, cancelled: intent.orderID };
    }
    if (intent.op === 'cancel_all') {
      if (market === 'futures') {
        const r = await mxRequest(creds, 'POST', 'futures', '/api/v1/private/order/cancel_all',
                                  null, { symbol: String(intent.symbol) }, route);
        if (!r.ok) return r;
        // Sweep untriggered plan stops too — terminal rule (states 1).
        for (let page = 1; page <= 10; page++) {
          const rp = await mxRequest(creds, 'GET', 'futures',
                                     '/api/v1/private/planorder/list/orders',
                                     [['page_num', String(page)], ['page_size', '100'],
                                      ['states', '1']], null, route);
          if (!rp.ok) return rp;
          const lst = Array.isArray((rp.data || {}).data) ? rp.data.data : [];
          for (const o of lst) {
            if (String((o || {}).symbol || '') !== String(intent.symbol)) continue;
            const sid = String(o.id || o.orderId || '');
            if (!sid) continue;
            const rc = await mxRequest(creds, 'POST', 'futures',
                                       '/api/v1/private/planorder/cancel', null,
                                       [{ symbol: String(intent.symbol), orderId: sid }], route);
            if (!rc.ok && !mexcCancelGone(rc.message)) return rc;
          }
          if (lst.length < 100) break;
        }
        return { ok: true, cancelled: 'all' };
      }
      const r = await mxRequest(creds, 'DELETE', 'spot', '/api/v3/openOrders',
                                [['symbol', String(intent.symbol)]], null, route);
      if (!r.ok) return r;
      return { ok: true, cancelled: 'all' };
    }
    const pr = await findPosRetry(fetchPos, intent.symbol);
    if (!pr.ok) return pr;
    if (intent.op === 'close') {
      if (!pr.pos) return { ok: false, message: 'Position not found' };
      const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
      const r = await place('futures', pr.pos.symbol, side, 'market', pr.pos.size,
                            null, intent.clOrdID, { reduceOnly: true });
      if (!r.ok) return r;
      return { ok: true, orderID: r.orderID, clOrdID: intent.clOrdID };
    }
    if (!pr.pos) return { ok: false, message: 'No open position to protect' };
    const terr = sltpTriggerOk(intent.kind, pr.pos.side, intent.trigger, pr.pos.mark);
    if (terr) return { ok: false, message: terr };
    const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
    const ordType = intent.kind === 'sl' ? 'stop' : 'tp_market';
    const r = await place('futures', pr.pos.symbol, side, ordType, pr.pos.size,
                          null, intent.clOrdID,
                          { reduceOnly: true, trigger: intent.trigger });
    if (!r.ok) return r;
    return { ok: true, kind: intent.kind, orderID: r.orderID, clOrdID: intent.clOrdID };
  }

  // --- Kraken (venue #14 — spot api.kraken.com + PF_ futures) ----------------
  // TWO SEPARATE key pairs — spot (kraken.com) and futures — since spot keys
  // cannot sign the futures API. Dual creds carry krv/key2/secret2; each
  // market signs ONLY with its own pair (fail-closed when missing); legacy
  // single-pair creds sign both hosts. Spot private = POST
  // form (nonce in body, API-Key/API-Sign); futures = urlencoded params with
  // APIKey/Authent/Nonce headers, signing path WITHOUT /derivatives.
  let krNonceLast = 0;
  function krNonce(baseMs) {
    let n = Math.round(Number(baseMs) || Date.now());
    if (n <= krNonceLast) n = krNonceLast + 1;
    krNonceLast = n;
    return String(n);
  }

  // Per-market pair resolve: dual creds (krv or key2 present) are STRICT —
  // a missing pair means that market fails closed; legacy single-pair
  // creds sign both markets (they were validated against both scopes).
  function krPairFor(creds, market) {
    const dual = !!(creds && (creds.krv || creds.key2 || creds.secret2));
    if (!dual) {
      return (creds && creds.key && creds.secret)
        ? { key: creds.key, secret: creds.secret } : null;
    }
    if (market === 'futures') {
      return (creds.key2 && creds.secret2)
        ? { key: creds.key2, secret: creds.secret2 } : null;
    }
    return (creds.key && creds.secret)
      ? { key: creds.key, secret: creds.secret } : null;
  }

  // Spot `EAPI:Invalid nonce` gets ONE retry with a forward-bumped nonce
  // (+1500ms lead): with key source "Server" the SAME spot key is shared by
  // the engine's REST polls and this signer — two independent ms-clock nonce
  // streams race and either can lose (Kraken nonces are strictly increasing
  // PER KEY). Never more than one retry: these errors count toward Kraken's
  // rate limit.
  const KR_NONCE_RETRY_LEAD_MS = 1500;
  // #1832 per-spot-key points ledgers (runtime map over the pure ledger).
  const krLedgers = {};   // spot api key → { pts, ts }
  function krLedgerFor(key) {
    return krLedgers[key] || (krLedgers[key] = krLedgerNew(Date.now()));
  }
  // #2168 re-import reservations (runtime map over the pure helpers): while
  // a re-import walk holds one for a spot key, routine queries on that key
  // skip so the ledger refills for the walk. Handle factory keyed by CRED
  // SLOT (what the reimport/backfill intents carry); the ledger itself is
  // per SPOT key — futures rides a separate limiter with no ledger, so a
  // futures-only pair yields an inert handle.
  const krResvs = krResvNew();
  function krResvFor(slot) {
    let key = null;
    try {
      const creds = credsGet(slot || 'kraken');
      const p = creds ? krPairFor(creds, 'spot') : null;
      key = p ? p.key : null;
    } catch (e) { key = null; }
    return {
      acquire: () => { if (key) krResvAcquire(krResvs, key, Date.now()); },
      release: () => { if (key) krResvRelease(krResvs, key); },
    };
  }
  // #1839 per-spot-key TRADING counters + order birth stamps (cancel age
  // penalties key on how old the order is at cancel time). Bounded map —
  // oldest stamps drop past 500 entries; a missing stamp = worst-case
  // penalty (cautious mirror).
  const krTradeLedgers = {};   // spot api key → { pts, ts }
  function krTradeLedgerFor(key) {
    return krTradeLedgers[key] || (krTradeLedgers[key] = krTradeLedgerNew(Date.now()));
  }
  const krOrderBirth = {};     // spot txid → placed-at ms
  function krOrderBirthRec(oid) {
    if (!oid) return;
    krOrderBirth[String(oid)] = Date.now();
    const ks = Object.keys(krOrderBirth);
    if (ks.length > 500) { for (let i = 0; i < ks.length - 400; i++) delete krOrderBirth[ks[i]]; }
  }
  function krOrderAgeS(oid) {
    const t = krOrderBirth[String(oid || '')];
    return t > 0 ? (Date.now() - t) / 1000 : null;   // null = unknown → worst case
  }
  // Spend on the trading mirror + one bounded diag row when it runs low
  // (the panel's amber pacing note keys off `paced` on the order ack).
  function krTradeSpendFor(key, cost, what) {
    const L = krTradeLedgerFor(key);
    const pts = krTradeSpend(L, cost, Date.now());
    if (pts < KR_TRADE_FLOOR) {
      tdiag('trade', 'kr_budget', { k: 'kraken', p: what, act: 'trade_low',
        cost: cost, tpts: Math.round(pts * 10) / 10 });
    }
    return pts;
  }
  // _pri: caller-declared priority — a query REQUIRED by a cancel flow (spot
  // cancel_all's OpenOrders id-discovery) rides the reserved lane: it never
  // defers/skips at the floor, and a body-level rate limit retries on the
  // bounded cancel deadline instead of failing the cancel silently.
  async function krRequest(creds, method, market, path, params, route, _nretry, _cxl0, _pri, _hot) {
    const pair = krPairFor(creds, market);
    if (!pair) {
      return { ok: false, message: market === 'futures'
        ? 'No Kraken futures API key saved — add a futures.kraken.com key pair'
        : 'No Kraken spot API key saved — add a kraken.com key pair' };
    }
    // #1832 points-ledger gate — spot private only, ABOVE the nonce/signer
    // path (a deferred call draws its nonce after the wait, so the monotonic
    // stream never inverts). Priority (order/cancel) never waits; queries
    // defer down to the cancel-reserved floor, or skip (fail-soft, logged).
    const krCC = market === 'futures' ? null : krCallCost(path);
    if (krCC && _pri) krCC.cls = 'cancel';   // reserved lane + loud retry
    if (krCC && !_nretry && !_cxl0) {
      const led = krLedgerFor(pair.key);
      // #2168: while a re-import walk holds a reservation on this key's
      // ledger, routine (non-hot, non-priority) queries skip IMMEDIATELY —
      // no points spent, no defer loop — so the ledger refills for the
      // walk. Same skipped:true shape/message the poll paths already
      // treat as fail-soft (kr_budget deferrals are fine and stay).
      // Orders/cancels never reach this branch (cls !== 'query').
      if (krCC.cls === 'query' && !_pri && !_hot
          && krResvHeld(krResvs, pair.key, Date.now())) {
        tdiag('trade', 'kr_budget', { k: 'kraken', p: path, act: 'resv_skip' });
        return { ok: false, skipped: true,
                 message: 'kr_budget: deferred by the rate-points ledger' };
      }
      const hotT0 = Date.now();   // #2131: bounded hot wait, never unbounded
      for (;;) {
        const g = krLedgerGate(led, krCC.cls, krCC.cost, Date.now());
        if (g.send) break;
        tdiag('trade', 'kr_budget', { k: 'kraken', p: path,
          act: g.skip ? 'skip' : 'defer', waitMs: g.waitMs,
          pts: Math.round(krLedgerPts(led, Date.now()) * 10) / 10,
          hot: _hot ? 1 : 0 });
        if (g.skip) {
          // #2131: a HOT read (user just traded on kraken) gets first claim
          // on the rate-points ledger — it WAITS for refill instead of being
          // skipped, bounded to 15s. Routine idle polls keep skipping (their
          // kr_budget deferrals are fine and stay). The ledger itself is
          // untouched — no extra points are ever spent.
          if (_hot && Date.now() - hotT0 < 15000) {
            await krWsSleep(Math.max(250, Math.min(g.waitMs || 250, 2000)));
            continue;
          }
          return { ok: false, skipped: true,
                   message: 'kr_budget: deferred by the rate-points ledger' };
        }
        await krWsSleep(g.waitMs);
      }
    }
    const plist = (params || []).slice();
    const headers = {};
    let host, query = '', bodyStr = null, m = method;
    if (market === 'futures') {
      host = KRAKEN_FUT_HOST;
      const postData = formEnc(plist);
      const nonce = krNonce(venueStampMs(await ensureVenueTime('kraken', 'futures', route)));
      let authent;
      try { authent = krFutSign(pair.secret, krFutSignPath(path), postData, nonce); }
      catch (e) { return { ok: false, message: 'Invalid API secret (not base64)' }; }
      headers['APIKey'] = pair.key;
      headers['Authent'] = authent;
      headers['Nonce'] = nonce;
      if (m === 'POST' || m === 'PUT') {
        bodyStr = postData;
        headers['Content-Type'] = 'application/x-www-form-urlencoded';
      } else {
        query = postData;
      }
    } else {
      host = KRAKEN_SPOT_HOST;
      const nonce = krNonce(venueStampMs(await ensureVenueTime('kraken', 'spot', route)));
      bodyStr = formEnc([['nonce', nonce]].concat(plist));
      let sign;
      try { sign = krSpotSign(pair.secret, path, nonce, bodyStr); }
      catch (e) { return { ok: false, message: 'Invalid API secret (not base64)' }; }
      headers['API-Key'] = pair.key;
      headers['API-Sign'] = sign;
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      m = 'POST';                       // spot private is always POST
    }
    let r;
    try {
      r = await httpJson(host, m, path, query, bodyStr, headers, route);
    } catch (e) { return transportFail(e, 'Kraken'); }
    if (r.status === 429) return { ok: false, message: 'Rate limited by Kraken — retry shortly' };
    let data;
    try { data = r.text ? JSON.parse(r.text) : {}; } catch (e) {
      return { ok: false, message: 'Kraken returned HTTP ' + r.status };
    }
    if (market === 'futures') {
      if (String((data || {}).result || '') === 'success') return { ok: true, data: data };
      const err = String((data || {}).error
        || (((data || {}).errors || [])[0] || '')
        || '') || (r.status >= 400 ? 'Kraken returned HTTP ' + r.status : 'Kraken error');
      return { ok: false, message: err };
    }
    const errs = (data || {}).error;
    if (Array.isArray(errs) && errs.length) {
      const msg = String(errs[0]);
      if (msg.indexOf('EAPI:Invalid nonce') >= 0 && !_nretry) {
        const bump = Date.now() + KR_NONCE_RETRY_LEAD_MS;
        if (bump > krNonceLast) krNonceLast = bump;
        return krRequest(creds, method, market, path, params, route, true, _cxl0, _pri, _hot);
      }
      // #1832: `EAPI:Rate limit` rides an HTTP 200 body — mirror venue truth
      // (drain our ledger so queries back off) and NEVER let a cancel fail
      // silently: retry with short backoff until it lands or the bounded
      // deadline passes, then fail LOUD (a silent failed Space is worse
      // than a late error).
      if (krIsRateLimited(msg) && krCC) {
        try { krLedgerDrain(krLedgerFor(pair.key), Date.now()); } catch (e) {}
        if (krCC.cls === 'cancel') {
          const t0 = _cxl0 || Date.now();
          if (Date.now() - t0 + KR_CANCEL_RETRY_GAP_MS < KR_CANCEL_RETRY_MS) {
            tdiag('trade', 'kr_budget', { k: 'kraken', p: path,
              act: 'cancel_retry', sinceMs: Date.now() - t0 });
            await krWsSleep(KR_CANCEL_RETRY_GAP_MS);
            return krRequest(creds, method, market, path, params, route,
                             _nretry, t0, _pri, _hot);
          }
          return { ok: false, message:
            'CANCEL FAILED — Kraken rate limit persisted ~5s (' + msg
            + ') — check open orders NOW' };
        }
      }
      return { ok: false, message: msg };
    }
    if (r.status >= 400) return { ok: false, message: 'Kraken returned HTTP ' + r.status };
    return { ok: true, data: data };
  }

  // --- Kraken private WS sessions (#1804) -----------------------------------
  // One session per cred slot: spot WS-v2 (token, executions+balances,
  // order entry) + futures ws/v1 (challenge-signed feeds). Started lazily
  // on the first acct read / order for the slot; reconnects with backoff;
  // closed on creds change/wipe. Whenever a socket is down, callers fall
  // back to the existing REST path (fail-visible via wsErr — the nonce
  // retry still guards that lane).
  let WSC = null;
  try { WSC = require('ws'); } catch (e) { /* fall back to REST-only */ }
  const KR_WS_ORDER_TIMEOUT_MS = 8000;
  const KR_WS_STALE_MS = 30000;          // no frame in 30s → treat as down
  const krWsSessions = {};               // slot → session
  function krWsSleep(ms) { return new Promise((res) => setTimeout(res, ms)); }

  // #1835: connection counter (per-conn diag ids — duplicated subscriptions
  // or overlapping reconnects show up as interleaved conn ids in kr_ws_lag).
  let krWsConnSeq = 0;
  // #1835: main-proc event-loop stall gauge — worst 1s-ticker drift since
  // the last kr_ws_lag emit. Separates shell-side stalls (OHLC poll bursts,
  // heavy snapshots) from venue-side delivery lag: a big WS lag with a flat
  // loopMax is Kraken's side; loopMax spikes matching the lag are ours.
  const KR_LAG_EMIT_MS = 60000;
  let krLoopTimer = null, krLoopMax = 0, krLoopLast = 0;
  function krLoopGaugeStart() {
    if (krLoopTimer) return;
    krLoopLast = Date.now();
    krLoopTimer = setInterval(() => {
      const now = Date.now();
      const drift = now - krLoopLast - 1000;
      if (drift > krLoopMax) krLoopMax = drift;
      krLoopLast = now;
    }, 1000);
    if (krLoopTimer.unref) krLoopTimer.unref();
  }
  function krLoopGaugeDrain() { const m = krLoopMax; krLoopMax = 0; return Math.max(0, Math.round(m)); }
  // Bounded per-minute emitter shared by both scopes.
  function krLagEmit(S, scopeKey) {
    const now = Date.now();
    if (!S.lag || now - (S.lagEmitT || 0) < KR_LAG_EMIT_MS) return;
    const sn = krLagSnap(S.lag);
    if (!sn) return;
    S.lagEmitT = now;
    sn.k = scopeKey;
    sn.loopMax = krLoopGaugeDrain();
    tdiag('trade', 'kr_ws_lag', sn);
  }

  function krWsSessGet(slot) { return krWsSessions[String(slot || 'kraken')] || null; }

  // #1876 tombstone re-add guard: true = the id was just removed (fill /
  // cancel / gone) and this re-add source must drop it. Diag rate-capped.
  function krTombBlock(sc, oid, w, ttl) {
    if (!sc || !oid) return false;
    // #1887: permanently-closed ids block every re-add source forever —
    // the TTL tombstone below only covers short-lag echoes.
    if (krClosedHas(sc.closed, oid)) {
      const nowC = Date.now();
      if (nowC - (sc._tombDiagT || 0) > 5000) {
        sc._tombDiagT = nowC;
        try { tdiag('acct', 'kr_closed_block', { w: w, oid: String(oid).slice(0, 24) }); } catch (e) { /* diag-only */ }
      }
      return true;
    }
    if (!krTombHit(sc.tombs, oid, Date.now(), ttl)) return false;
    const now = Date.now();
    if (now - (sc._tombDiagT || 0) > 5000) {
      sc._tombDiagT = now;
      try { tdiag('acct', 'kr_tomb_block', { w: w, oid: String(oid).slice(0, 24) }); } catch (e) { /* diag-only */ }
    }
    return true;
  }

  // #1887 oid→symbol learn + symbol-less fill catch-up (spot scope). Called
  // from every authoritative symbol source (own ACKs, WS registrations,
  // symbol-carrying exec rows). When cached symbol-less fills exist for the
  // oid (S._symless counter — fill beat the ACK/registration), they are
  // stamped in place (fills_read serves the same raw objects), their totals
  // delta is applied exactly once (_totApplied latch — the original fill
  // site no-ops without a symbol and only IT or this drain may apply), and
  // a symbol-complete seed row re-pushes so the panel's lot accumulator
  // seeds this beat (fid re-push dedupes as sound-seen; lane merge dedupes
  // by eid — the fixed row simply lands where the null one never did).
  function krOidSymLearn(S, oid, sym) {
    if (!S || !oid || !sym) return;
    S.oidSym = krOidSymNote(S.oidSym, String(oid), sym);
    if (!((S._symless | 0) > 0)) return;
    const fixed = krFillsSymBackfill(S.fills && S.fills.rows, String(oid), sym);
    if (!fixed.length) return;
    S._symless = Math.max(0, (S._symless | 0) - fixed.length);
    for (const raw of fixed) {
      // #1890: the drain rides the SAME exactly-once gate as the live exec
      // path — a balances delta that already named/covered this trade must
      // not be re-added on top of the venue-true absolute balance.
      const rid = String(raw.exec_id || raw.trade_id || '');
      const rts = raw.timestamp ? Date.parse(raw.timestamp) : 0;
      if (!raw._totApplied && S.totals &&
          !krFillIngestGate(S.applied, S.balTs, raw.symbol, rid,
                            Number.isFinite(rts) ? rts : 0)) {
        raw._totApplied = true;
        if (rid) S.applied = krClosedAdd(S.applied || { m: {}, q: [] }, rid);
      }
      if (!raw._totApplied && S.totals) {
        const tn = Date.now();
        if (!S.fillDirs) S.fillDirs = {};
        const touched = krFillTotalsApply(S.totals, raw, S.fillDirs, tn);
        if (touched.length) {
          raw._totApplied = true;
          if (rid) S.applied = krClosedAdd(S.applied || { m: {}, q: [] }, rid);   // #1890 shared ingest ledger
          if (!S.fillTouch) S.fillTouch = {};
          for (const a of touched) S.fillTouch[a] = tn;
          krFillTouchPrune(S.fillTouch, tn);
          krFillDirsPrune(S.fillDirs, tn);
          krLseq(S); krPushSc(S, 'bal');
        }
      }
      const fr = krWsSpotFillRow(raw);
      if (fr) { krLseq(S); krPushSc(S, 'fill', fr.id, krPushFillRow(raw, null)); }
    }
  }

  // --- #1867 push channel (runtime) ---------------------------------------
  // Every ledger mutation site below calls krPushSc(scope, kind) right after
  // its krLseq bump. Marks coalesce KR_PUSH_COALESCE_MS, then ONE event per
  // scope goes out through opts.pushLedger (main.js broadcasts it to every
  // panel window) with the scope's CURRENT lseq. The flush also busts the
  // acct_read memo so the push-triggered panel re-read can't be served a
  // pre-mutation snapshot. No pushLedger callback (old shell wiring / web) →
  // everything stays a no-op and the poll remains the only display trigger.
  const krPushPend = {};
  let krPushTimer = null;
  function krPushFlush() {
    krPushTimer = null;
    const evs = krPushDrain(krPushPend, (key) => {
      const ix = key.indexOf('|');
      const sess = krWsSessGet(key.slice(0, ix));
      const sc = sess && (key.slice(ix + 1) === 'fut' ? sess.fut : sess.spot);
      return sc ? sc.lseq : 0;
    }, Date.now());
    for (const ev of evs) {
      try { execAcctRead.bust('kraken', ev.slot); } catch (e) { /* pre-init */ }
      try { execAcctRead.markHot('kraken'); } catch (e) { /* #2131 hot lane */ }
      try { pushLedgerCb(ev); } catch (e) { /* window gone mid-send */ }
      tdiag('acct', 'kr_push', { s: ev.scope, q: ev.seq, k: ev.kinds.join(',') });
    }
  }
  function krPushSc(scope, kind, id, row) {
    // #1876: EVERY gone-order removal tombstones here (single choke point —
    // fill-consumed, cancel-ACKed, WS-gone and audit-confirmed deletes all
    // push 'ordgone'), so lagging snapshots/echoes can't resurrect the row.
    // Runs BEFORE the push-wiring guard: web/no-push shells tombstone too.
    if (scope && String(kind) === 'ordgone' && id != null && id !== '') {
      scope.tombs = krTombAdd(scope.tombs, String(id), Date.now());
      // #1887: gone is PERMANENT for the session — the closed set outlives
      // every tombstone TTL, so a late registration / stale snapshot /
      // /state render can never reopen the id (gone-before-registration).
      scope.closed = krClosedAdd(scope.closed, String(id));
    }
    if (!pushLedgerCb || !scope || !scope._pk) return;
    krPushMark(krPushPend, scope._pk, kind, id, row);
    if (!krPushTimer) {
      krPushTimer = setTimeout(krPushFlush, KR_PUSH_COALESCE_MS);
      if (krPushTimer && typeof krPushTimer.unref === 'function') krPushTimer.unref();
    }
  }

  function krWsClose(slot) {
    const s = krWsSessions[String(slot || 'kraken')];
    if (!s) return;
    s.closed = true;
    for (const side of ['spot', 'fut']) {
      const S = s[side];
      if (S && S.ws) { try { S.ws.terminate(); } catch (e) { /* gone */ } }
    }
    delete krWsSessions[String(slot || 'kraken')];
  }
  function krWsCloseAll(venue) {
    for (const k of Object.keys(krWsSessions)) {
      if (k === venue || k.indexOf(String(venue) + '#') === 0) krWsClose(k);
    }
  }

  function krWsFailPending(S, msg) {
    for (const rid of Object.keys(S.pending || {})) {
      const fut = S.pending[rid];
      delete S.pending[rid];
      try { fut.reject(new Error(msg || 'Kraken spot WS closed')); } catch (e) { /* raced */ }
    }
  }

  // Live = subscribed AND a frame within the stale window (heartbeats
  // arrive ~1s on both sockets, so a quiet account still ticks).
  function krWsLive(S) {
    return !!(S && S.up && S.ws && Date.now() - (S.lastMsg || 0) < KR_WS_STALE_MS);
  }

  function krWsEnsure(slot, creds, route) {
    slot = String(slot || 'kraken');
    let s = krWsSessions[slot];
    if (!WSC) return null;
    // change-detection tail from the RESOLVED pairs (signing discipline:
    // never touch raw creds fields — krPairFor owns dual-pair routing)
    const ps = krPairFor(creds, 'spot');
    const pf = krPairFor(creds, 'futures');
    const tail = ((ps && ps.key) || '') + '|' + ((pf && pf.key) || '');
    if (s && s.tail !== tail) { krWsClose(slot); s = null; }
    if (!s) {
      s = krWsSessions[slot] = {
        tail: tail, closed: false, route: routeNorm(route),
        spot: { running: false, up: false, ws: null, err: null, lastMsg: 0,
                orders: {}, totals: null, reqId: 0, pending: {},
                fills: { rows: [], seen: {} } },
        fut: { running: false, up: false, ws: null, err: null, lastMsg: 0,
               orders: {}, positions: null, flex: null,
               fills: { rows: [], seen: {} } },
      };
      // #1867: push-channel scope tags — mutation sites push via the scope
      // object itself (WS handlers don't all carry the slot).
      s.spot._pk = slot + '|spot';
      s.fut._pk = slot + '|fut';
    }
    if (krPairFor(creds, 'spot') && !s.spot.running) krWsSpotLoop(slot, s, creds);
    if (krPairFor(creds, 'futures') && !s.fut.running) krWsFutLoop(slot, s, creds);
    krLoopGaugeStart();                       // #1835: stall gauge rides sessions
    return s;
  }

  function krWsDial(url, route) {
    const ag = agentFor(route);
    if (ag.refuse) return null;
    const opts = { handshakeTimeout: 15000 };
    if (ag.agent !== undefined) opts.agent = ag.agent;
    return new WSC(url, opts);
  }

  function krWsSpotLoop(slot, s, creds) {
    s.spot.running = true;
    (async () => {
      let backoff = 2000;
      while (krWsSessions[slot] === s && !s.closed) {
        const tok = await krRequest(creds, 'POST', 'spot',
                                    '/0/private/GetWebSocketsToken', null, s.route);
        if (s.closed || krWsSessions[slot] !== s) break;
        let token = null;
        if (tok.ok) token = ((((tok.data || {}).result) || {}).token) || null;
        if (!token) {
          const perm = krWsPermMsg(tok.message || '');
          s.spot.err = perm || ('Kraken WS token fetch failed: '
                                + (tok.message || 'no token'));
          await krWsSleep(perm ? 300000 : backoff);
          backoff = Math.min(backoff * 2, 60000);
          continue;
        }
        try {
          await krWsSpotConn(slot, s, token);
          backoff = 2000;
        } catch (e) {
          s.spot.err = 'Kraken spot WS: ' + ((e && e.message) || 'error');
        }
        s.spot.up = false; s.spot.ws = null;
        krWsFailPending(s.spot);
        if (s.closed || krWsSessions[slot] !== s) break;
        await krWsSleep(backoff);
        backoff = Math.min(backoff * 2, 60000);
      }
      s.spot.running = false;
    })().catch(() => { s.spot.running = false; });
  }

  function krWsSpotConn(slot, s, token) {
    return new Promise((resolve, reject) => {
      const ws = krWsDial(KRAKEN_SPOT_WS_URL, s.route);
      if (!ws) { reject(new Error('proxy unavailable')); return; }
      const S = s.spot;
      // #1835: fresh per-connection lag recorder (base rolling-min resets
      // with the conn — a reconnect must not inherit the old clock baseline)
      S.lag = krLagNew(++krWsConnSeq);
      let settled = false;
      const done = (err) => {
        if (settled) return; settled = true;
        clearInterval(idleT);
        try { ws.terminate(); } catch (e) { /* gone */ }
        if (S.ws === ws) { S.ws = null; S.up = false; }
        if (err) reject(err); else resolve();
      };
      const subs = {};
      const idleT = setInterval(() => {
        const idle = Date.now() - (S.lastMsg || 0);
        if (idle > KR_WS_STALE_MS * 2) done(new Error('stream stalled'));
        else if (idle > 15000) { try { ws.ping(); } catch (e) { /* dying */ } }
      }, 5000);
      ws.on('open', () => {
        S.lastMsg = Date.now();
        // reconnect seed-race: THIS connection has not snapshotted yet —
        // a stale seeded=true from the previous socket would let an empty
        // fills_read succeed before the fresh snapshot lands.
        if (S.fills) S.fills.seeded = false;
        try {
          // snap_trades: the subscribe-time snapshot back-records the 50
          // most recent trades — the fills seed window (#1814; fills made
          // before the socket came up must not stick OPEN in the blotter).
          ws.send(JSON.stringify({ method: 'subscribe', params: {
            channel: 'executions', token: token,
            snap_orders: true, snap_trades: true } }));
          ws.send(JSON.stringify({ method: 'subscribe', params: {
            channel: 'balances', token: token } }));
        } catch (e) { done(e); }
      });
      ws.on('pong', () => { S.lastMsg = Date.now(); });
      ws.on('message', (buf) => {
        S.lastMsg = Date.now();
        let msg;
        try { msg = JSON.parse(String(buf)); } catch (e) { return; }
        if (!msg || typeof msg !== 'object') return;
        if (msg.method === 'subscribe') {
          if (!msg.success) {
            done(new Error('subscribe failed: '
                           + String(msg.error || 'rejected')));
            return;
          }
          subs[String(((msg.result || {}).channel) || '')] = 1;
          if (subs.executions && subs.balances && !S.up) {
            S.ws = ws; S.up = true; S.err = null; S.token = token;
          }
          return;
        }
        if (msg.req_id != null && S.pending[msg.req_id]) {
          const fut = S.pending[msg.req_id];
          delete S.pending[msg.req_id];
          fut.resolve(msg);
          return;
        }
        if (msg.channel === 'executions') {
          // #1835: stamp arrival BEFORE processing; apply time measured over
          // the whole frame (snapshot frames skip lag samples — bulk historic
          // timestamps would fake seconds of "lag").
          const lagArrMs = Date.now();
          const lagT0 = (typeof performance !== 'undefined' && performance.now)
            ? performance.now() : null;
          const lagSnapFrame = String(msg.type || '') === 'snapshot';
          if (String(msg.type || '') === 'snapshot') {
            // #1876: snapshot-sourced removals ride the SAME omission grace
            // as the REST auditor — never a blind reset (the old krSynCarry
            // reset wiped every confirmed row a lagging snapshot omitted;
            // observed: resting badges gone with ZERO kr_audit_omit).
            // Snapshot ids = rows the frame lists as open; young rows and
            // first omissions are withheld (diag kr_audit_omit w:'snap');
            // tombstoned ids the snapshot omits are confirmed gone.
            {
              const snapT0 = Date.now();
              const snapIds = [];
              for (const e0 of (msg.data || [])) {
                if (!e0 || typeof e0 !== 'object') continue;
                const oid0 = String(e0.order_id || '');
                const st0 = String(e0.order_status || '').toLowerCase();
                if (oid0 && st0 && !KR_WS_SPOT_GONE[st0]) snapIds.push(oid0);
              }
              const rec = krOrdersReconcile(S.orders, snapIds, snapT0, snapT0);
              if (rec.omit.length) {
                tdiag('acct', 'kr_audit_omit', { w: 'snap',
                  n: rec.omit.length, ids: rec.omit.slice(0, 6).join(',').slice(0, 80) });
              }
              if (rec.gone.length) {
                krLseq(S);
                for (const g of rec.gone) krPushSc(S, 'ordgone', g);   // #1867/#1874
              }
              // #1878: a snapshot that OMITS known-live rows (withheld
              // above) has proven itself Kraken-side stale — it must not
              // clear removal tombstones (its omission of a removed id
              // confirms nothing) and its adds stay tombstone-gated below.
              if (!rec.omit.length) S.tombs = krTombConfirm(S.tombs, snapIds, snapT0);
              else tdiag('acct', 'kr_snap_stale', { w: 'snap', n: rec.omit.length });
            }
            // #1814: the snap_trades snapshot IS the fills seed — until it
            // lands, fills_read must NOT report this scope (an empty read
            // would advance the panel cursor past the seed window).
            if (S.fills) S.fills.seeded = true;
          }
          // #1884: order registrations apply BEFORE trade rows within one
          // frame — a market order whose consuming fill rides the SAME frame
          // always finds its ledger row (fill-close no longer no-ops).
          for (const e of krExecsOrderFirst(msg.data)) {
            if (!e || typeof e !== 'object') continue;
            // #1814: trade executions feed the native fills cache (dedupe
            // by exec_id — snapshot + live overlap is a no-op). Snapshot
            // trade rows may carry NO order_status: never let one land in
            // the open-orders map as a phantom row.
            // #1887: symbol backfill BEFORE anything consumes the row —
            // instant-fill limits deliver trade rows whose order was never
            // registered, so the old order-row-only backfill starved the
            // totals math, the pushed seed row AND the poll copy at once.
            // Sources: ledger order row → oid→symbol memory (own ACKs /
            // earlier registrations). Symbol-carrying rows LEARN instead.
            if (String(e.exec_type || '') === 'trade') {
              const soid = String(e.order_id || '');
              if (e.symbol == null || e.symbol === '') {
                const bs = (soid && S.orders[soid] && S.orders[soid].symbol != null)
                  ? S.orders[soid].symbol : krOidSymGet(S.oidSym, soid);
                if (bs) e.symbol = bs;
              } else if (soid) {
                S.oidSym = krOidSymNote(S.oidSym, soid, e.symbol);
              }
            }
            const fr = krWsSpotFillRow(e);
            if (fr) {
              const frNew = krFillsCachePush(S.fills, fr);
              // #1887: count cached symbol-less rows — the ACK/registration
              // learn path drains them (bounded backfill scan gated on >0)
              if (frNew && (e.symbol == null || e.symbol === '')) {
                S._symless = (S._symless | 0) + 1;
              }
            }
            // #1864 fills-first posrow: a LIVE trade execution applies its
            // balance delta to the totals map synchronously (buy +base/-cost,
            // sell -base/+cost, fees off their own asset) — the posrow moves
            // NOW, the ~3-6s-late balances echo / REST auditor only confirms.
            // Touched assets stamp a grace window so a venue snapshot taken
            // BEFORE this fill can't clobber the local value right back.
            if (fr && !lagSnapFrame && S.totals) {
              const tnow0 = Date.now();
              if (!S.fillDirs) S.fillDirs = {};   // #1884 auditor regression clamp
              // #1890 exactly-once gate: skip when this trade id already
              // ingested via ANY path (duplicate delivery, learn-drain, or a
              // balances delta whose ledger ref named it) or when an APPLIED
              // balances row for the base asset covers the fill's venue ts
              // (the absolute balance includes it — adding the delta again
              // doubled the posrow qty and got sell-all rejected).
              if (!krFillIngestGate(S.applied, S.balTs, e.symbol, fr.id, fr.ts)) {
                e._totApplied = true;   // the learn-drain must not re-apply either
                if (!S.applied) S.applied = { m: {}, q: [] };
                S.applied = krClosedAdd(S.applied, fr.id);
              } else {
                const touched = krFillTotalsApply(S.totals, e, S.fillDirs, tnow0);
                if (touched.length) {
                  e._totApplied = true;   // #1887: the learn-drain must not re-apply
                  S.applied = krClosedAdd(S.applied || { m: {}, q: [] }, fr.id);   // #1890 shared ingest ledger
                  if (!S.fillTouch) S.fillTouch = {};
                  const tnow = tnow0;
                  for (const a of touched) S.fillTouch[a] = tnow;
                  krFillTouchPrune(S.fillTouch, tnow);
                  krFillDirsPrune(S.fillDirs, tnow);
                  krLseq(S); krPushSc(S, 'bal');   // #1867 fills-first posrow beat
                }
              }
            }
            if (fr && !lagSnapFrame) { krLseq(S); krPushSc(S, 'fill', fr.id, krPushFillRow(e, S.orders[String(e.order_id || '')])); }   // #1867 push-driven chime (+#1870 per-fill id, +#1878 posrow-seed row) — seq MUST advance per live fill or back-to-back fill-only frames dedupe as stale
            if (fr) {
              // #1870 fill-consumption badge removal: a trade execution that
              // fully consumes its order deletes the ledger row in the SAME
              // frame (badge del rides this push beat, never a later "order
              // gone" confirmation); partial fills update the row qty.
              // Snapshot rows stay barred from the open-orders map (helper
              // returns null for status-less unknown rows; lagSnapFrame rows
              // only ever confirm/consume an EXISTING row).
              // #1876: a trade echo on a just-removed order must not
              // recreate its row (late partial-fill updates resurrect)
              const foid = String(e.order_id || '');
              const hadRow = !!(foid && S.orders[foid]);
              const eff = krTombBlock(S, foid, 'sfill')
                ? null : krFillOrderApply(S.orders, e, Date.now());
              // #1884: a LIVE fill whose order row was ABSENT (fill beat the
              // registration) records into the consumed-set — a later
              // registration (WS or snapshot) for the id closes immediately
              // instead of opening it (no /state ghost, TTL-independent).
              if (!lagSnapFrame && foid && !hadRow && !S.orders[foid]) {
                if (!S.consumed) S.consumed = {};
                const st84 = String(e.order_status || '').toLowerCase();
                const gone84 = !!KR_WS_SPOT_GONE[st84] || eff === 'gone';
                krConsumedNote(S.consumed, foid, {
                  lastQty: e.last_qty, cumQty: e.cum_qty, orderQty: e.order_qty,
                  gone: gone84, exec: e,
                }, Date.now());
                // #1891: a gone-consuming fill with NO ledger row (never
                // registered in this session) still closes the id NOW —
                // unconditional closed-set entry at gone-processing time +
                // the goid rides the push so every panel window kills the
                // badge this beat (the old row-gated push skipped these, so
                // a stale snapshot / ACK-shadow chip lingered 10-15s until
                // a budget-deferred OpenOrders render). Symbol backfill for
                // the panel's lot accumulator stays on the #1887 learn-drain
                // (krOidSymLearn runs BEFORE the closed gate at registration).
                if (gone84) { krLseq(S); krPushSc(S, 'ordgone', foid); }
              }
              // #1874: fill-consumed rows push the gone oid — every panel
              // window tombstones the badge in the same push apply pass
              if (eff) { krLseq(S); krPushSc(S, eff === 'gone' ? 'ordgone' : 'order', eff === 'gone' ? String(e.order_id || '') : null); }   // #1860/#1867/#1874
              continue;
            }
            const oid = String(e.order_id || '');
            if (!oid) continue;
            // #1887: EVERY registration/status row carrying a symbol teaches
            // the oid→symbol map and drains cached symbol-less fills for the
            // id — BEFORE the closed/tombstone gate, so a gone-before-
            // registration order still ships its symbol-complete fills to
            // the panel's lot accumulator (external orders have no own ACK).
            if (e.symbol != null && e.symbol !== '') krOidSymLearn(S, oid, e.symbol);
            if (KR_WS_SPOT_GONE[String(e.order_status || '').toLowerCase()]) {
              delete S.orders[oid];
              krLseq(S); krPushSc(S, 'ordgone', oid);   // #1874 WS-gone badge fast path
              continue;
            } else {
              // #1876: lagging echo/snapshot row for a just-removed order —
              // the tombstone wins, never a badge resurrection. #1878:
              // snapshot rows are gated at the LONG snap TTL (stale pages
              // apply 10-20s late under budget); live deltas keep 12s.
              if (krTombBlock(S, oid, lagSnapFrame ? 'ssnap' : 'sord',
                              lagSnapFrame ? KR_TOMB_SNAP_TTL_MS : null)) continue;
              // #1884: registration for an id own fills already CONSUMED
              // (fill beat the registration — same/next push) closes NOW
              // instead of opening; the pending exec rows ship their
              // symbol-backfilled fill rows so the panel's lot accumulator
              // still seeds this beat (fid re-push dedupes as sound-seen).
              const cr84 = S.consumed
                ? krConsumedTake(S.consumed, oid, e, Date.now()) : null;
              if (cr84) {
                for (const pe of cr84.execs) {
                  const pfr = krWsSpotFillRow(pe);
                  if (pfr) { krLseq(S); krPushSc(S, 'fill', pfr.id, krPushFillRow(pe, e)); }
                }
                if (cr84.eff === 'gone') {
                  delete S.orders[oid];
                  krLseq(S); krPushSc(S, 'ordgone', oid);   // #1884 close-on-late-registration
                  continue;
                }
              }
              // delta frames carry partial fields — merge onto the row
              S.orders[oid] = Object.assign({}, S.orders[oid] || {}, e);
              // #1884: partially-consumed pending fills carry their running
              // cum_qty onto the fresh row (the next fill can complete it)
              if (cr84 && cr84.cq > 0 &&
                  !(Number(S.orders[oid].cum_qty) >= cr84.cq)) {
                S.orders[oid].cum_qty = cr84.cq;
              }
              // #1874: birth stamp (WS add seq/time) — the audit-omission
              // grace keys on it; live frames only (snapshot rows carry
              // historic orders whose birth predates this session)
              if (!lagSnapFrame && S.orders[oid]._bornTs == null) {
                S.orders[oid]._bornTs = Date.now();
              }
              // #1822: a real venue echo confirms the optimistic synthetic row
              delete S.orders[oid]._synTs;
              // #1828: last-WS-write stamp — the post-confirm reconcile's
              // grace window (a row the venue just echoed must not be eaten
              // by an OpenOrders page fetched moments earlier)
              S.orders[oid]._updTs = Date.now();
            }
            krLseq(S); krPushSc(S, 'order');   // #1860 ledger mutation seq / #1867 push
          }
          // #1835: per-event venue-ts → arrival lag (live frames only) +
          // frame apply time; bounded per-minute diag emit.
          if (!lagSnapFrame && S.lag) {
            const applyUs = lagT0 == null ? NaN
              : Math.round((performance.now() - lagT0) * 1000);
            for (const e of (msg.data || [])) {
              if (!e || !e.timestamp) continue;
              const vts = Date.parse(e.timestamp);
              if (Number.isFinite(vts)) krLagRec(S.lag, lagArrMs - vts, applyUs);
            }
            krLagEmit(S, 'kraken:spot');
          }
        } else if (msg.channel === 'balances') {
          const balSnap = String(msg.type || '') === 'snapshot';
          if (balSnap || S.totals == null) S.totals = {};
          for (const r of (msg.data || [])) {
            if (!r || typeof r !== 'object') continue;
            const a = String(r.asset || '').toUpperCase();
            if (!a || r.balance == null) continue;
            // #1890 exactly-once fill ingest: a delta whose ledger refs name
            // a trade the local fill math has NOT applied is NEW venue truth
            // (the balances delta beat the executions echo — the old skip-
            // then-add path double-counted the lot-opening fill). Note the
            // refs into the shared applied-set (the exec row skips its
            // apply) and let the row THROUGH the fill-touch grace; refs
            // already applied = the ordinary lagging echo → grace unchanged.
            let freshRef = false, refTs = 0;
            if (!balSnap) {
              const br = krBalRowRefs(r);
              refTs = br.ts;
              if (br.refs.length && !S.applied) S.applied = { m: {}, q: [] };
              for (const ref of br.refs) {
                if (!krClosedHas(S.applied, ref)) {
                  S.applied = krClosedAdd(S.applied, ref);
                  freshRef = true;
                }
              }
            }
            // #1864: delta echoes lag fills by seconds — an asset the local
            // fill math touched within the grace keeps the LOCAL value
            // (snapshot frames reset the map, so they always apply).
            if (!balSnap && !freshRef && S.fillTouch && S.fillTouch[a] != null &&
                Date.now() - S.fillTouch[a] <= KR_FILL_TOUCH_GRACE_MS) continue;
            S.totals[a] = r.balance;
            // #1890: venue-ts cover stamp — only rows that ACTUALLY applied
            // may claim the balance covers fills up to refTs (a grace-
            // skipped row proved nothing about the stored value).
            if (refTs) {
              if (!S.balTs) S.balTs = {};
              if (!(S.balTs[a] >= refTs)) S.balTs[a] = refTs;
            }
          }
          krLseq(S); krPushSc(S, 'bal');   // #1860 ledger mutation seq / #1867 push
        }
        // status / heartbeat / pong frames → lastMsg bump only
      });
      ws.on('error', (e) => done(e || new Error('ws error')));
      ws.on('close', () => done(new Error('stream closed')));
    });
  }

  // One spot WS-v2 request/reply (add_order / cancel_order). Errors carry
  // .krWsDown=true when NOTHING was sent (safe REST fallback); post-send
  // failures don't (caller must not blind-resend an order).
  function krWsSpotCall(s, method, params) {
    const S = s && s.spot;
    return new Promise((resolve, reject) => {
      if (!krWsLive(S)) {
        const e = new Error('Kraken spot WS not connected');
        e.krWsDown = true; reject(e); return;
      }
      S.reqId += 1;
      const rid = S.reqId;
      const p = Object.assign({}, params || {}, { token: S.token });
      const t = setTimeout(() => {
        if (S.pending[rid]) {
          delete S.pending[rid];
          reject(new Error('Kraken spot WS timed out'));
        }
      }, KR_WS_ORDER_TIMEOUT_MS);
      S.pending[rid] = {
        resolve: (m) => { clearTimeout(t); resolve(m); },
        reject: (err) => { clearTimeout(t); reject(err); },
      };
      try {
        S.ws.send(JSON.stringify({ method: method, params: p, req_id: rid }));
      } catch (e2) {
        delete S.pending[rid];
        clearTimeout(t);
        const e = new Error('Kraken spot WS send failed');
        e.krWsDown = true; reject(e);
      }
    });
  }

  function krWsFutLoop(slot, s, creds) {
    s.fut.running = true;
    const pair = krPairFor(creds, 'futures');
    (async () => {
      let backoff = 2000;
      while (krWsSessions[slot] === s && !s.closed) {
        try {
          await krWsFutConn(s, pair);
          backoff = 2000;
        } catch (e) {
          s.fut.err = 'Kraken futures WS: ' + ((e && e.message) || 'error');
        }
        s.fut.up = false; s.fut.ws = null;
        if (s.closed || krWsSessions[slot] !== s) break;
        await krWsSleep(backoff);
        backoff = Math.min(backoff * 2, 60000);
      }
      s.fut.running = false;
    })().catch(() => { s.fut.running = false; });
  }

  function krWsFutConn(s, pair) {
    return new Promise((resolve, reject) => {
      const ws = krWsDial(KRAKEN_FUT_WS_URL, s.route);
      if (!ws) { reject(new Error('proxy unavailable')); return; }
      const F = s.fut;
      // #1835: fresh per-connection lag recorder (see spot twin)
      F.lag = krLagNew(++krWsConnSeq);
      let settled = false;
      let snapOrders = false, snapPos = false;
      const done = (err) => {
        if (settled) return; settled = true;
        clearInterval(idleT);
        try { ws.terminate(); } catch (e) { /* gone */ }
        if (F.ws === ws) { F.ws = null; F.up = false; }
        if (err) reject(err); else resolve();
      };
      const idleT = setInterval(() => {
        if (Date.now() - (F.lastMsg || 0) > KR_WS_STALE_MS * 2) {
          done(new Error('stream stalled'));
        }
      }, 5000);
      const ready = () => {
        // serve the futures scope only once ALL THREE surfaces exist —
        // a partial WS view must never spoof an empty account
        if (snapOrders && snapPos && F.flex != null && !F.up) {
          F.ws = ws; F.up = true; F.err = null;
        }
      };
      ws.on('open', () => {
        F.lastMsg = Date.now();
        // reconnect seed-race: fills_snapshot for THIS connection is still
        // pending — clear the previous socket's seeded latch (fail-closed).
        if (F.fills) F.fills.seeded = false;
        try { ws.send(JSON.stringify({ event: 'challenge', api_key: pair.key })); }
        catch (e) { done(e); }
      });
      ws.on('message', (buf) => {
        F.lastMsg = Date.now();
        let msg;
        try { msg = JSON.parse(String(buf)); } catch (e) { return; }
        if (!msg || typeof msg !== 'object') return;
        const ev = String(msg.event || '');
        if (ev === 'challenge' && msg.message) {
          let signed;
          try { signed = krFutWsSign(pair.secret, msg.message); }
          catch (e) { done(new Error('invalid futures secret')); return; }
          try {
            for (const feed of ['open_orders', 'open_positions', 'balances', 'fills']) {
              ws.send(JSON.stringify({ event: 'subscribe', feed: feed,
                                       api_key: pair.key,
                                       original_challenge: msg.message,
                                       signed_challenge: signed }));
            }
            ws.send(JSON.stringify({ event: 'subscribe', feed: 'heartbeat' }));
          } catch (e) { done(e); }
          return;
        }
        if (ev === 'error' || ev === 'alert') {
          done(new Error(String(msg.message || 'futures ws error')));
          return;
        }
        const feed = String(msg.feed || '');
        if (feed === 'open_orders_snapshot') {
          // #1876: same omission-grace rule as the spot snapshot — removals
          // ride krOrdersReconcile (birth grace + double omission, withheld
          // omissions diag kr_audit_omit w:'fsnap'), never a blind reset.
          {
            const snapT0 = Date.now();
            const snapIds = [];
            for (const o0 of (msg.orders || [])) {
              const oid0 = String((o0 || {}).order_id || '');
              if (oid0) snapIds.push(oid0);
            }
            const rec = krOrdersReconcile(F.orders, snapIds, snapT0, snapT0);
            if (rec.omit.length) {
              tdiag('acct', 'kr_audit_omit', { w: 'fsnap',
                n: rec.omit.length, ids: rec.omit.slice(0, 6).join(',').slice(0, 80) });
            }
            if (rec.gone.length) {
              krLseq(F);
              for (const g of rec.gone) krPushSc(F, 'ordgone', g);   // #1867/#1874
            }
            // #1878: an omitting (proven-stale) snapshot never clears
            // removal tombstones; its adds stay gated below at the snap TTL
            if (!rec.omit.length) F.tombs = krTombConfirm(F.tombs, snapIds, snapT0);
            else tdiag('acct', 'kr_snap_stale', { w: 'fsnap', n: rec.omit.length });
          }
          for (const o of (msg.orders || [])) {
            const oid = String((o || {}).order_id || '');
            if (oid) {
              if (krTombBlock(F, oid, 'fsnap', KR_TOMB_SNAP_TTL_MS)) continue;   // #1876 just-removed — no resurrection (#1878 snap TTL)
              // #1884: snapshot listing an id own fills already consumed —
              // never (re)open it; push the gone id so badges die everywhere
              if (F.consumed && F.consumed[oid] &&
                  (krConsumedTake(F.consumed, oid, o, Date.now()) || {}).eff === 'gone') {
                if (F.orders[oid]) { delete F.orders[oid]; }
                krLseq(F); krPushSc(F, 'ordgone', oid);
                continue;
              }
              // #1874: keep the birth stamp across snapshot re-delivery
              if (F.orders[oid] && F.orders[oid]._bornTs != null) {
                o._bornTs = F.orders[oid]._bornTs;
              }
              F.orders[oid] = o;
            }
          }
          krLseq(F); krPushSc(F, 'order');   // #1860 ledger mutation seq / #1867 push
          snapOrders = true; ready();
        } else if (feed === 'open_orders') {
          const o = msg.order;
          if (o && typeof o === 'object') {
            const oid = String(o.order_id || '');
            if (oid) {
              if (msg.is_cancel) {
                delete F.orders[oid];
                krLseq(F); krPushSc(F, 'ordgone', oid);   // #1874 WS-gone badge fast path
              } else if (krTombBlock(F, oid, 'ford')) {
                // #1876: lagging delta for a just-removed order — no resurrection
              } else if (F.consumed && F.consumed[oid] &&
                         (krConsumedTake(F.consumed, oid, o, Date.now()) || {}).eff === 'gone') {
                // #1884: own fills already consumed this order (fill beat
                // the registration) — close NOW instead of opening a ghost
                delete F.orders[oid];
                krLseq(F); krPushSc(F, 'ordgone', oid);
              } else {
                // #1874: birth stamp on first WS add (kept across updates)
                if (F.orders[oid] && F.orders[oid]._bornTs != null) {
                  o._bornTs = F.orders[oid]._bornTs;
                } else if (o._bornTs == null) o._bornTs = Date.now();
                F.orders[oid] = o;
                // #1860 (mirrors spot): a venue echo confirms the optimistic
                // synthetic and stamps last-WS-write so the reconcile grace /
                // REST-fallback overlay treat the row as WS-confirmed fresh.
                delete F.orders[oid]._synTs;
                F.orders[oid]._updTs = Date.now();
                // #1894: ship the added/updated row (REST shape) so the panel
                // badge renders off THIS push beat, not the next acct read
                krLseq(F); krPushSc(F, 'order', null, krWsFutOrderRest(F.orders[oid]));   // #1860 / #1867 / #1894
              }
            }
          } else if (msg.order_id) {
            delete F.orders[String(msg.order_id)];
            krLseq(F); krPushSc(F, 'ordgone', String(msg.order_id));   // #1860 / #1867 / #1874
          }
        } else if (feed === 'open_positions') {
          F.positions = msg.positions || [];
          // #1867: position DELTA push — identity signature only (instrument/
          // size/entry), so PnL-only re-deliveries never spam the channel.
          {
            const sig = krFutPosSig(F.positions);
            if (F._posSig !== sig) {
              F._posSig = sig;
              krLseq(F); krPushSc(F, 'pos');
            }
          }
          snapPos = true; ready();
        } else if (feed === 'balances_snapshot' || feed === 'balances') {
          if (msg.flex_futures && typeof msg.flex_futures === 'object') {
            F.flex = msg.flex_futures;
            ready();
          }
        } else if (feed === 'fills_snapshot' || feed === 'fills') {
          // #1814: native fills cache — the snapshot (last 100 fills) is
          // the futures seed back-record; fill_id dedupes the overlap.
          // NOT part of ready() (fills never gate trading), but the seeded
          // flag gates fills_read: an empty read before the snapshot lands
          // would advance the panel cursor past the seed window.
          const lagArrMs = Date.now();          // #1835: stamp before apply
          const lagT0 = (typeof performance !== 'undefined' && performance.now)
            ? performance.now() : null;
          for (const f of (msg.fills || [])) {
            const fr = krWsFutFillRow(f);
            if (fr) krFillsCachePush(F.fills, fr);
            // #1870: live fills consume their order row NOW — remaining→0
            // deletes the badge in this push beat (the open_orders echo
            // that used to drive it lags seconds); remaining>0 updates qty.
            if (feed === 'fills' && fr) {
              // #1876: no order-row writes for a just-removed order
              const foid = String((f || {}).order_id || '');
              const hadRow = !!(foid && F.orders[foid]);
              const eff = krTombBlock(F, foid, 'ffill')
                ? null : krFutFillOrderApply(F.orders, f, Date.now());
              // #1884: fill beat the open_orders registration — remember the
              // consumption (remaining_order_qty is authoritative) so the
              // late registration closes instead of opening a ghost row.
              if (foid && !hadRow && !F.orders[foid]) {
                if (!F.consumed) F.consumed = {};
                const rq84 = Number((f || {}).remaining_order_qty);
                const gone84 = eff === 'gone' || (Number.isFinite(rq84) && rq84 <= 0);
                krConsumedNote(F.consumed, foid, {
                  lastQty: (f || {}).qty, remaining: rq84, gone: gone84,
                }, Date.now());
                // #1891: fully-consumed fill with NO ledger row → close the
                // id NOW (unconditional closed-set entry + panel goid push),
                // mirroring the spot scope — never wait for a snapshot.
                if (gone84) { krLseq(F); krPushSc(F, 'ordgone', foid); }
              }
              // #1874: fill-consumed rows push the gone oid (badge fast path)
              if (eff) { krLseq(F); krPushSc(F, eff === 'gone' ? 'ordgone' : 'order', eff === 'gone' ? String(f.order_id || '') : null); }   // #1860/#1867/#1874
              // per-fill push id (#1870): each live fill rides the event so
              // the panel chime plays per fill at push time
              // #1905: the raw row rides the push too — the panel's fills
              // lane, posrow overlay and push-beat blotter POST consume it
              // without waiting out the fills_read cadence.
              krLseq(F); krPushSc(F, 'fill', fr.id, krPushFutFillRow(f));   // seq advances per live fill (snapshot rows never bump)
            }
          }
          if (feed === 'fills_snapshot' && F.fills) F.fills.seeded = true;
          // #1835: live fill frames only (snapshot = historic timestamps)
          if (feed === 'fills' && F.lag) {
            const applyUs = lagT0 == null ? NaN
              : Math.round((performance.now() - lagT0) * 1000);
            for (const f of (msg.fills || [])) {
              const vts = Number((f || {}).time);
              if (vts > 0) krLagRec(F.lag, lagArrMs - vts, applyUs);
            }
            krLagEmit(F, 'kraken:fut');
          }
        }
        // heartbeat frames → liveness only
      });
      ws.on('error', (e) => done(e || new Error('ws error')));
      ws.on('close', () => done(new Error('stream closed')));
    });
  }

  // Public product specs (TTL): futures PF_ steps + spot altname/lot steps.
  // Full-catalog GETs — pass a raised response cap (shell httpJson defaults
  // to 256 KB; AssetPairs/instruments exceed it → masked "unknown symbol").
  let krProdCache = null;
  async function krProducts(route) {
    if (krProdCache && Date.now() - krProdCache.ts < PRODUCTS_TTL_MS) return krProdCache.v;
    const cap = 8 * 1024 * 1024;
    const v = { futures: {}, spot: {}, spotCode: {} };
    try {
      const rf = await httpJson(KRAKEN_FUT_HOST, 'GET', '/derivatives/api/v3/instruments',
                                '', null, {}, route, cap);
      const df = JSON.parse(rf.text);
      for (const s of ((df || {}).instruments || [])) {
        const sym = String((s || {}).symbol || '');
        if (sym.indexOf('PF_') !== 0 || s.tradeable === false) continue;
        v.futures[sym] = { qty_step: krDecStep(s.contractValueTradePrecision) || '1' };
      }
    } catch (e) { /* fail-visible at order time (spec miss) */ }
    try {
      const rs = await httpJson(KRAKEN_SPOT_HOST, 'GET', '/0/public/AssetPairs',
                                '', null, {}, route, cap);
      const ds = JSON.parse(rs.text);
      const res = ((ds || {}).result) || {};
      for (const code of Object.keys(res)) {
        const s = res[code] || {};
        if (String(s.status || '') !== 'online') continue;
        const ws = s.wsname;
        if (typeof ws !== 'string' || ws.indexOf('/') < 0) continue;
        const fix = { XBT: 'BTC', XDG: 'DOGE' };
        const sym = ws.split('/').map((p) => fix[p] || p).join('/');
        v.spot[sym] = { alt: String(s.altname || code),
                        qty_step: krDecStep(s.lot_decimals) || '1' };
        // #1820: pair-code → display symbol (TradesHistory rows name the
        // pair by CODE or altname; the REST fills seed maps them here)
        v.spotCode[code] = sym;
        v.spotCode[String(s.altname || code)] = sym;
      }
    } catch (e) { /* fail-visible at order time (spec miss) */ }
    if (Object.keys(v.futures).length || Object.keys(v.spot).length) {
      krProdCache = { ts: Date.now(), v: v };
    }
    return v;
  }

  async function execKraken(creds, intent, route) {
    const market = intent.market === 'spot' ? 'spot' : 'futures';
    // Warm the private WS for this slot (first order may still ride REST;
    // subsequent ones go nonce-free over the socket).
    try { krWsEnsure(intent.credSlot || 'kraken', creds, route); } catch (e) { /* REST path */ }
    const fetchPos = async () => {
      const r = await krRequest(creds, 'GET', 'futures',
                                '/derivatives/api/v3/openpositions', null, route);
      if (!r.ok) return r;
      return { ok: true, rows: krPositionRows(r.data) };
    };
    async function place(mkt, symbol, side, ordType, qty, price, clOrdID, flags) {
      const f = flags || {};
      const t = String(ordType).toLowerCase();
      const isStop = t === 'stop' || t === 'stop_limit' || t === 'tp_market';
      const prods = await krProducts(route);
      if (mkt !== 'futures') {
        // Spot conditional orders are deliberately NOT offered (futures-only
        // stops — engine parity, same honest gate as MEXC spot).
        if (isStop) return { ok: false, message: 'Stop orders are futures-only on Kraken' };
        const spec = prods.spot[symbol];
        if (!spec || !spec.alt) return { ok: false, message: 'Unknown spot symbol ' + symbol };
        let qv = String(qty);
        if (t === 'market' && String(side).toLowerCase() === 'buy') {
          // Spot market BUY arrives QUOTE-denominated — convert via the live
          // best ask; a failed ticker read FAILS the order (never a guess).
          let ask = null;
          try {
            const rt = await httpJson(KRAKEN_SPOT_HOST, 'GET', '/0/public/Ticker',
                                      formEnc([['pair', spec.alt]]), null, {}, route);
            const res = ((JSON.parse(rt.text) || {}).result) || {};
            for (const k of Object.keys(res)) {
              const a = (res[k] || {}).a;
              if (Array.isArray(a) && a.length) ask = Number(a[0]);
              break;
            }
          } catch (e) { return transportFail(e, 'Kraken'); }
          if (!(ask > 0)) return { ok: false, message: 'Price lookup failed: empty ticker' };
          qv = String(Number(qty) / ask);
        }
        const q = krQtyFloor(qv, spec.qty_step);
        if (q == null || !(Number(q) > 0)) {
          return { ok: false, message: 'Quantity below the step for ' + symbol };
        }
        // #1839: TRADING-counter soft gate (add cost 1) — below the reserved
        // floor the add waits a bounded beat then sends ANYWAY, flagged
        // `paced` on the ack (panel shows the amber pacing note). Gated
        // HERE (op level) because WS order entry bypasses krRequest but
        // counts against the same venue trading limiter.
        let krPaced = false;
        {
          const krTP = krPairFor(creds, 'spot');
          if (krTP) {
            const tg = krTradeGate(krTradeLedgerFor(krTP.key), 1, Date.now());
            if (tg.paced) {
              krPaced = true;
              tdiag('trade', 'kr_budget', { k: 'kraken', p: 'AddOrder',
                act: 'trade_pace', waitMs: tg.waitMs,
                tpts: Math.round(krTradePts(krTradeLedgerFor(krTP.key), Date.now()) * 10) / 10 });
              await krWsSleep(tg.waitMs);
            }
            krTradeSpendFor(krTP.key, 1, 'AddOrder');
          }
        }
        // #1804: WS-first order entry (nonce-free + lower latency). KrWsDown
        // (nothing sent) → REST fallback; post-send timeout → surface
        // "state unknown", NEVER a blind REST re-send.
        const sessO = krWsSessGet(intent.credSlot || 'kraken');
        if (sessO && krWsLive(sessO.spot)) {
          const wp = { symbol: symbol,
                       side: String(side).toLowerCase() === 'buy' ? 'buy' : 'sell',
                       order_type: t === 'limit' ? 'limit' : 'market',
                       order_qty: Number(q) };
          if (t === 'limit') wp.limit_price = Number(price);
          const cid = krClOrdId(clOrdID);
          if (cid) wp.cl_ord_id = cid;
          let m;
          try { m = await krWsSpotCall(sessO, 'add_order', wp); }
          catch (e) {
            if (e && e.krWsDown) { m = null; }        // fall through to REST
            else return { ok: false, message: 'Kraken WS order state unknown — check open orders before retrying' };
          }
          if (m) {
            if (!m.success) {
              return { ok: false, message: String(m.error || 'Kraken rejected the order') };
            }
            const oid = String(((m.result || {}).order_id) || '');
            if (!oid) return { ok: false, message: 'Kraken returned no order id' };
            // #1822: the ACK precedes the executions echo by seconds over
            // proxied routes — echo the resting order into S.orders NOW so
            // badges/holds don't wait on the venue echo.
            // #1887: the ACK is the earliest oid→symbol authority (the
            // symbol is the intent's) — learn + drain any symbol-less fills
            // the WS echo delivered BEFORE this ACK returned (instant fill).
            krOidSymLearn(sessO.spot, oid, symbol);
            // #1887: an instant-fill limit can be CLOSED (fill + gone
            // processed) before the ACK returns — the optimistic echo must
            // never reopen a closed/tombstoned id (badge resurrection).
            if (t === 'limit' && !krTombBlock(sessO.spot, oid, 'ack')) {
              sessO.spot.orders[oid] =
                krSynSpotOrder(oid, symbol, side, q, price, cid, Date.now());
              krLseq(sessO.spot); krPushSc(sessO.spot, 'order');   // #1860/#1867
            }
            krOrderBirthRec(oid);   // #1839 cancel age-penalty anchor
            const okW = { ok: true, orderID: oid, clOrdID: krClOrdId(clOrdID) };
            if (krPaced) okW.paced = true;
            return okW;
          }
        }
        const params = krSpotOrderParams(spec.alt, side, t, q, price, clOrdID);
        const r = await krRequest(creds, 'POST', 'spot', '/0/private/AddOrder', params, route);
        if (!r.ok) return r;
        const txids = (((r.data || {}).result) || {}).txid || [];
        const oid = txids.length ? String(txids[0]) : '';
        if (!oid) return { ok: false, message: 'Kraken returned no order id' };
        if (sessO) krOidSymLearn(sessO.spot, oid, symbol);   // #1887 ACK symbol authority
        if (t === 'limit' && sessO && !krTombBlock(sessO.spot, oid, 'ack')) {   // #1822 optimistic echo (REST ack); #1887 closed ids never reopen
          sessO.spot.orders[oid] = krSynSpotOrder(oid, symbol, side, q, price,
                                                  krClOrdId(clOrdID), Date.now());
          krLseq(sessO.spot); krPushSc(sessO.spot, 'order');   // #1860/#1867
        }
        krOrderBirthRec(oid);   // #1839 cancel age-penalty anchor
        const okR = { ok: true, orderID: oid, clOrdID: krClOrdId(clOrdID) };
        if (krPaced) okR.paced = true;
        return okR;
      }
      const spec = prods.futures[symbol];
      const q = krQtyFloor(qty, (spec || {}).qty_step);
      if (q == null || !(Number(q) > 0)) {
        return { ok: false, message: 'Quantity below the step for ' + symbol };
      }
      const params = krFutOrderParams(symbol, side, t, q, price, clOrdID,
                                      { reduceOnly: !!f.reduceOnly, trigger: f.trigger });
      if (params == null) return { ok: false, message: 'Unsupported order type ' + ordType };
      const r = await krRequest(creds, 'POST', 'futures',
                                '/derivatives/api/v3/sendorder', params, route);
      if (!r.ok) return r;
      const ss = ((r.data || {}).sendStatus) || {};
      const st = String(ss.status || '');
      const oid = String(ss.order_id || ss.orderId || '');
      if (st !== 'placed' || !oid) {
        // Kraken encodes rejects INSIDE a result:"success" envelope
        // (insufficientAvailableFunds & co.) — surface verbatim.
        return { ok: false, message: st || 'Kraken rejected the order' };
      }
      // #1822 optimistic echo — plain resting limits only (stops live on the
      // trigger feed, market orders never rest); positions stay venue-truth.
      if (t === 'limit' && !isStop && !f.trigger) {
        const sessF = krWsSessGet(intent.credSlot || 'kraken');
        // #1887: instant-fill limit closed before the ACK returned — the
        // optimistic echo must never reopen a closed/tombstoned id.
        if (sessF && !krTombBlock(sessF.fut, oid, 'ack')) {
          sessF.fut.orders[oid] = krSynFutOrder(oid, symbol, side, q, price,
                                                krClOrdId(clOrdID),
                                                !!f.reduceOnly, Date.now());
          krLseq(sessF.fut); krPushSc(sessF.fut, 'order');   // #1860/#1867
        }
      }
      return { ok: true, orderID: oid, clOrdID: krClOrdId(clOrdID) };
    }
    if (intent.op === 'order') {
      return place(market, intent.symbol, intent.side, intent.type,
                   intent.qty, intent.price, intent.clOrdID,
                   { reduceOnly: !!intent.reduceOnly, trigger: intent.trigger });
    }
    if (intent.op === 'cancel') {
      if (market === 'futures') {
        const r = await krRequest(creds, 'POST', 'futures',
                                  '/derivatives/api/v3/cancelorder',
                                  [['order_id', String(intent.orderID)]], route);
        if (!r.ok) return r;
        const cs = ((r.data || {}).cancelStatus) || {};
        const st = String(cs.status || '');
        if (st !== 'cancelled') return { ok: false, message: st || 'Kraken rejected the cancel' };
        const sessF = krWsSessGet(intent.credSlot || 'kraken');   // #1822
        if (sessF) { delete sessF.fut.orders[String(intent.orderID)]; krLseq(sessF.fut); krPushSc(sessF.fut, 'ordgone', String(intent.orderID)); }   // #1860/#1867/#1874
        return { ok: true, cancelled: intent.orderID };
      }
      // #1839: TRADING-counter spend — cancel age penalty (young orders cost
      // up to +8 pts). Never gated: cancels are the priority, the mirror
      // just records the cost so order adds keep headroom for them.
      {
        const krTP = krPairFor(creds, 'spot');
        if (krTP) {
          krTradeSpendFor(krTP.key, krCancelPenalty(krOrderAgeS(intent.orderID)),
                          'CancelOrder');
        }
      }
      // #1804: WS cancel first — cancels are idempotent, so ANY WS failure
      // safely falls back to REST.
      const sessC = krWsSessGet(intent.credSlot || 'kraken');
      if (sessC && krWsLive(sessC.spot)) {
        try {
          const m = await krWsSpotCall(sessC, 'cancel_order',
                                       { order_id: [String(intent.orderID)] });
          if (m && m.success) {
            delete sessC.spot.orders[String(intent.orderID)];   // #1822
            krLseq(sessC.spot); krPushSc(sessC.spot, 'ordgone', String(intent.orderID));   // #1860/#1867/#1874
            return { ok: true, cancelled: intent.orderID };
          }
        } catch (e) { /* REST fallback below */ }
      }
      const r = await krRequest(creds, 'POST', 'spot', '/0/private/CancelOrder',
                                [['txid', String(intent.orderID)]], route);
      if (!r.ok) return r;
      if (sessC) { delete sessC.spot.orders[String(intent.orderID)]; krLseq(sessC.spot); krPushSc(sessC.spot, 'ordgone', String(intent.orderID)); }   // #1822/#1860/#1867/#1874
      return { ok: true, cancelled: intent.orderID };
    }
    if (intent.op === 'amend') {
      // #1864 replace gesture: spot WS-v2 amend_order moves a working limit
      // in ONE call — the order id (and queue priority at the new price
      // level) survives, the trading counter pays cost 1 and NO cancel age
      // penalty (+8 on young orders is where burst headroom used to go).
      // Eligibility is strict: spot + live private WS; anything else returns
      // fallback:true so the panel degrades to cancel+add. Every decision is
      // diag-logged (kr_amend) with the mode taken.
      const px = Number(intent.price);
      if (!(px > 0)) return { ok: false, message: 'Amend needs a price' };
      if (market === 'futures') {
        tdiag('trade', 'kr_amend', { k: 'kraken', mode: 'fallback', why: 'futures' });
        return { ok: false, fallback: true, message: 'Amend is spot-only on Kraken' };
      }
      const sessM = krWsSessGet(intent.credSlot || 'kraken');
      if (!(sessM && krWsLive(sessM.spot))) {
        tdiag('trade', 'kr_amend', { k: 'kraken', mode: 'fallback', why: 'ws_down' });
        return { ok: false, fallback: true, message: 'Kraken spot WS not connected' };
      }
      {
        const krTP = krPairFor(creds, 'spot');
        if (krTP) krTradeSpendFor(krTP.key, 1, 'AmendOrder');
      }
      let m;
      try {
        m = await krWsSpotCall(sessM, 'amend_order',
                               { order_id: String(intent.orderID), limit_price: px });
      } catch (e) {
        if (e && e.krWsDown) {
          tdiag('trade', 'kr_amend', { k: 'kraken', mode: 'fallback', why: 'ws_down' });
          return { ok: false, fallback: true, message: 'Kraken spot WS not connected' };
        }
        // post-send timeout: the amend MAY have applied — never blind
        // cancel+add on top (a doubled order is worse than a stale price).
        tdiag('trade', 'kr_amend', { k: 'kraken', mode: 'unknown' });
        return { ok: false, message: 'Kraken WS amend state unknown — check the order before retrying' };
      }
      if (!m || !m.success) {
        // explicit venue reject (filled/canceled/unsupported): surface it —
        // the caller decides; a gone-family order needs no move anyway.
        tdiag('trade', 'kr_amend', { k: 'kraken', mode: 'reject',
          err: String((m && m.error) || '').slice(0, 80) });
        return { ok: false, message: String((m && m.error) || 'Kraken rejected the amend') };
      }
      const oidA = String(intent.orderID);
      if (sessM.spot.orders[oidA]) {
        sessM.spot.orders[oidA] = Object.assign({}, sessM.spot.orders[oidA],
          { limit_price: px, _updTs: Date.now() });
        krLseq(sessM.spot); krPushSc(sessM.spot, 'order');   // #1860/#1867
      }
      tdiag('trade', 'kr_amend', { k: 'kraken', mode: 'ws', ok: 1 });
      return { ok: true, orderID: oidA, amended: true };
    }
    if (intent.op === 'cancel_all') {
      if (market === 'futures') {
        // cancelallorders?symbol sweeps EVERYTHING on the contract —
        // untriggered stops included (they live in the same book).
        const r = await krRequest(creds, 'POST', 'futures',
                                  '/derivatives/api/v3/cancelallorders',
                                  [['symbol', String(intent.symbol)]], route);
        if (!r.ok) return r;
        const sessF = krWsSessGet(intent.credSlot || 'kraken');   // #1822
        if (sessF) {
          // #1876: swept ids ride the ordgone choke point (tombstones)
          for (const g of krSynSweepSymbol(sessF.fut.orders, intent.symbol, 'instrument')) krPushSc(sessF.fut, 'ordgone', g);
          krLseq(sessF.fut); krPushSc(sessF.fut, 'order');   // #1867
        }
        return { ok: true, cancelled: 'all' };
      }
      // #1839: Space = ONE bulk sweep. The old loop of per-txid cancels
      // (OpenOrders discovery + N calls) charged N age penalties on the
      // TRADING counter — 15 sweeps of young orders exhausted it and Kraken
      // rejected the sweeps themselves ("rate limit persisted ~5s" with live
      // orders resting). Kraken's bulk endpoints are ONE round trip and ONE
      // penalty charge: WS-v2 `cancel_all` when the private socket is live
      // (nonce-free), REST /0/private/CancelAll otherwise. Both are
      // ACCOUNT-WIDE (spot has no per-pair sweep) — acceptable: the flow
      // this exists for scalps a single pair.
      const sessA = krWsSessGet(intent.credSlot || 'kraken');   // #1822
      {
        const krTP = krPairFor(creds, 'spot');
        if (krTP) krTradeSpendFor(krTP.key, 8, 'CancelAll');   // one worst-case penalty
      }
      const sweepOk = (count) => {
        // account-wide sweep → drop EVERY optimistic/echoed spot row (all
        // pairs), so holds/badges reflect the sweep immediately.
        if (sessA) {
          // #1876: per-oid ordgone (tombstones) — a lagging snapshot/REST
          // page must not resurrect swept badges
          for (const k of Object.keys(sessA.spot.orders || {})) {
            delete sessA.spot.orders[k];
            krPushSc(sessA.spot, 'ordgone', k);
          }
          krLseq(sessA.spot); krPushSc(sessA.spot, 'order');   // #1860/#1867
        }
        const out = { ok: true, cancelled: 'all' };
        if (count != null) out.count = count;
        return out;
      };
      if (sessA && krWsLive(sessA.spot)) {
        try {
          const m = await krWsSpotCall(sessA, 'cancel_all', {});
          if (m && m.success) {
            return sweepOk(Number(((m.result || {}).count)) || 0);
          }
          // explicit WS reject → keep going: cancels are idempotent, the
          // REST bulk sweep below is the loud-or-clean authority.
        } catch (e) { /* WS down/timeout → REST bulk sweep below */ }
      }
      // Priority lane + bounded rate-limit retry (krCallCost class 'cancel')
      // — the loud "CANCEL FAILED" path is unchanged.
      const r = await krRequest(creds, 'POST', 'spot', '/0/private/CancelAll',
                                null, route);
      if (!r.ok) {
        // #1839 stale-state knock-on guard: a REJECTED sweep leaves the
        // local mirror wrong (rows Kraken already dropped / rows still
        // live) and the very next gestures cascade ("EOrder:Unknown order"
        // cancels, "EOrder:Insufficient funds" re-sells against phantom
        // holds). Force ONE immediate OpenOrders reconcile on the priority
        // lane so truth lands before the user's next action. Best-effort —
        // the sweep failure itself stays the loud error.
        try {
          const loSeq0 = sessA ? (sessA.spot.lseq | 0) : 0;   // #1870 stale guard
          const loT0 = Date.now();   // #1874 snapshot fetch-start stamp
          const lo = await krRequest(creds, 'POST', 'spot', '/0/private/OpenOrders',
                                     null, route, null, null, true);
          const loMap = ((((lo.data || {}).result) || {}).open);
          if (lo.ok && sessA &&
              krAuditGate(loSeq0, sessA.spot.lseq | 0,
                          !!(loMap && typeof loMap === 'object')) === 'apply') {
            const ids = Object.keys(loMap);
            // #1860: this auditor correction deletes displayed rows — the
            // ledger seq must advance with them
            const rec = krOrdersReconcile(sessA.spot.orders, ids, Date.now(), loT0);
            if (rec.omit.length) {   // #1874 withheld snapshot omissions
              tdiag('acct', 'kr_audit_omit', { k: 'kraken', w: 'sweep',
                n: rec.omit.length, ids: rec.omit.slice(0, 6).join(',').slice(0, 80) });
            }
            if (rec.gone.length) {
              krLseq(sessA.spot);
              for (const g of rec.gone) krPushSc(sessA.spot, 'ordgone', g);   // #1867/#1874
            }
          }
        } catch (e) { /* best-effort */ }
        return r;
      }
      return sweepOk(Number((((r.data || {}).result) || {}).count) || 0);
    }
    const pr = await findPosRetry(fetchPos, intent.symbol);
    if (!pr.ok) return pr;
    if (intent.op === 'close') {
      if (!pr.pos) return { ok: false, message: 'Position not found' };
      const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
      const r = await place('futures', pr.pos.symbol, side, 'market', pr.pos.size,
                            null, intent.clOrdID, { reduceOnly: true });
      if (!r.ok) return r;
      return { ok: true, orderID: r.orderID, clOrdID: intent.clOrdID };
    }
    if (!pr.pos) return { ok: false, message: 'No open position to protect' };
    const terr = sltpTriggerOk(intent.kind, pr.pos.side, intent.trigger, pr.pos.mark);
    if (terr) return { ok: false, message: terr };
    const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
    const ordType = intent.kind === 'sl' ? 'stop' : 'tp_market';
    const r = await place('futures', pr.pos.symbol, side, ordType, pr.pos.size,
                          null, intent.clOrdID,
                          { reduceOnly: true, trigger: intent.trigger });
    if (!r.ok) return r;
    return { ok: true, kind: intent.kind, orderID: r.orderID, clOrdID: intent.clOrdID };
  }

  // --- Hyperliquid (DEX — wallet-signed /exchange actions) --------------------
  // #2008: every shell-side background /info rides the weight-paced budgeter
  // queue (429 → shared backoff + up to 2 bounded retries); /exchange order
  // sends bypass the queue and only debit the bucket (see hlExchange).
  const _hlBudget = hlBudgetMake(1000, Date.now());
  let _hlBudgetT = null;
  function _hlBudgetPump() {
    for (;;) {
      const r = hlBudgetNext(_hlBudget, Date.now());
      if (r.item) { try { r.item.res(); } catch (e) {} continue; }
      if (r.wait >= 0 && !_hlBudgetT)
        _hlBudgetT = setTimeout(() => { _hlBudgetT = null; _hlBudgetPump(); }, r.wait);
      return;
    }
  }
  function _hlBudgetGate(typ) {
    return new Promise((res) => {
      _hlBudget.q[hlInfoTier(String(typ || ''))].push(
        { w: hlInfoWeight(String(typ || '')), res: res });
      _hlBudgetPump();
    });
  }
  async function hlInfo(body, route) {
    for (let a = 0; a < 3; a++) {
      await _hlBudgetGate(body && body.type);
      let r;
      try {
        // #2016: hlInfo-wide raised response cap — heavy list types
        // (userFillsByTime 2000-row pages, historicalOrders, candleSnapshot)
        // routinely exceed httpJson's 256 KB default; a truncated body made
        // JSON.parse throw and EVERY backfill page failed as "malformed JSON"
        // (see shell-httpjson-response-cap). 8 MB = the cat_fetch bridge cap.
        r = await httpJson(HL_HOST, 'POST', '/info', '', JSON.stringify(body), {}, route,
                           8 * 1024 * 1024);
      } catch (e) { return transportFail(e, 'Hyperliquid'); }
      if (r.status === 429) {
        hlBudget429(_hlBudget, Date.now(), 0);
        if (a < 2) continue;
        return { ok: false, message: 'Rate limited by Hyperliquid — retry shortly' };
      }
      hlBudgetOk(_hlBudget);
      if (r.status !== 200) return { ok: false, message: 'Hyperliquid returned HTTP ' + r.status };
      try { return { ok: true, data: JSON.parse(r.text) }; } catch (e) {
        return { ok: false, message: 'Hyperliquid returned malformed JSON' };
      }
    }
    return { ok: false, message: 'Rate limited by Hyperliquid — retry shortly' };
  }

  async function hlExchangeOnce(creds, action, route) {
    // #2008: order sends never queue — debit the shared bucket so background
    // /info pauses while order flow is hot (never the reverse).
    try { hlBudgetSpend(_hlBudget, 1, Date.now()); _hlBudgetPump(); } catch (e) {}
    const nonce = dexSign.hlNextNonce();
    let sig;
    try { sig = dexSign.hlSignAction(String(creds.secret).trim(), action, nonce); }
    catch (e) { return { ok: false, message: 'Hyperliquid signing failed: ' + ((e && e.message) || 'error') }; }
    const payload = { action: action, nonce: nonce, signature: sig, vaultAddress: null };
    let r;
    try {
      r = await httpJson(HL_HOST, 'POST', '/exchange', '', JSON.stringify(payload), {}, route);
    } catch (e) { return transportFail(e, 'Hyperliquid'); }
    if (r.status === 429) return { ok: false, alim: true, message: 'Rate limited by Hyperliquid — retry shortly' };
    let data;
    try { data = JSON.parse(r.text); } catch (e) {
      return { ok: false, message: 'Hyperliquid returned HTTP ' + r.status };
    }
    const res = dexSign.hlExchangeResult(data);
    if (!res.ok) {
      // in-band per-ADDRESS action-budget reject (HTTP 200) — flagged so the
      // paced retry lane below re-signs and re-sends at 1/s.
      if (hlAlimHit(0, res.message)) return { ok: false, alim: true, message: res.message };
      return { ok: false, message: res.message };
    }
    return { ok: true, st: res.st };
  }
  // #2016 per-ADDRESS rate-limit FIFO queue: every /exchange action (order/
  // cancel/modify — they share the address budget) is its own queue entry on
  // one paced 1/s lane per creds slot; distinct gestures are NEVER dropped by
  // newer ones (FIFO, urgent reduce/cancel jumps front). Each retry re-signs
  // (fresh nonce). Total latency per gesture bounded (~6s) — on expiry the
  // final result keeps `alim:true` so the panel toasts + rolls back its
  // optimistic badges. `alimQ` carries the queue depth for the chip.
  const hlAlimLanes = {};
  async function hlExchange(creds, action, route) {
    const laneK = String((creds && (creds.key || creds.secret)) || 'hl');
    const lane = hlAlimLanes[laneK] || (hlAlimLanes[laneK] = hlAlimLane());
    const e = hlAlimBegin(lane, hlActionUrgent(action), Date.now());
    const myR = e.rseq;
    let lastR = null;
    try {
      for (let attempt = 0; ; ) {
        // FIFO pace gate: first send goes straight out on an unlimited lane
        // (zero added latency); once the address is limited — or this gesture
        // already ate a reject — every send waits for its queue turn.
        if (lane.limited || attempt > 0) {
          const nx = hlAlimNext(lane, e, myR, attempt, Date.now(),
                                HL_ALIM_MAX_TRIES, HL_ALIM_DEADLINE_MS);
          if (nx.wait) { await new Promise((rs) => setTimeout(rs, nx.wait)); continue; }
          if (!nx.retry) {
            if (nx.superseded) {
              tdiag('alim', 'superseded', { attempt: attempt });
              return { ok: false, alim: true, superseded: true,
                       message: 'Superseded by a retry of the same action' };
            }
            tdiag('alim', 'give_up', { tries: attempt, ms: Date.now() - e.t0, qd: lane.q.length - 1 });
            return lastR || { ok: false, alim: true, alimQ: Math.max(0, lane.q.length - 1),
                              message: 'Hyperliquid address limit — send expired, not placed' };
          }
          if (attempt > 0) tdiag('alim', 'retry', { attempt: attempt, delayMs: 0 });
        }
        const r = await hlExchangeOnce(creds, action, route);
        if (!(r && r.alim)) {
          if (r && r.ok && lane.limited) { lane.limited = false; tdiag('alim', 'clear', { tries: attempt + 1 }); }
          return r;
        }
        lane.limited = true;
        r.alimQ = Math.max(0, lane.q.length - 1);
        lastR = r;
        attempt++;
      }
    } finally { hlAlimDone(lane, e); }
  }

  // Product-spec cache: main meta + spotMeta parsed once per TTL; HIP-3
  // builder dexes ('xyz:PLTR') are fetched ON DEMAND per dex (no 30-dex
  // sweep on the desktop — one order touches exactly one dex).
  const hlProds = { ts: 0, futures: null, spot: null, wireMap: null };
  const hlBuilders = {};                 // dex → { ts, specs }

  function hlParsePerps(meta) {
    const out = {};
    const uni = (meta && meta.universe) || [];
    for (let i = 0; i < uni.length; i++) {
      const u = uni[i] || {};
      const name = String(u.name || '');
      if (!name || u.isDelisted) continue;
      out[name] = { symbol: name, wire: name, asset: i,
                    sz_decimals: parseInt(u.szDecimals, 10) || 0 };
    }
    return out;
  }
  function hlParseBuilderPerps(meta, dex, dexIndex) {
    const out = {};
    const uni = (meta && meta.universe) || [];
    for (let i = 0; i < uni.length; i++) {
      const u = uni[i] || {};
      let name = String(u.name || '');
      if (!name || u.isDelisted) continue;
      if (name.indexOf(':') < 0) name = dex + ':' + name;
      out[name] = { symbol: name, wire: name,
                    asset: dexSign.HL_BUILDER_ASSET_BASE
                           + dexIndex * dexSign.HL_BUILDER_ASSET_STRIDE + i,
                    sz_decimals: parseInt(u.szDecimals, 10) || 0 };
    }
    return out;
  }
  function hlParseSpot(smeta) {
    const tokens = {};
    for (const t of (smeta && smeta.tokens) || []) tokens[parseInt(t.index, 10)] = t;
    const out = {}, wireMap = {};
    for (const pair of (smeta && smeta.universe) || []) {
      const wire = String((pair || {}).name || '');
      const toks = (pair || {}).tokens || [];
      const b = tokens[parseInt(toks[0], 10)], q = tokens[parseInt(toks[1], 10)];
      if (!wire || !b || !q) continue;
      const key = String(b.name) + '/' + String(q.name);
      if (out[key] && !pair.isCanonical) continue;
      out[key] = { symbol: key, wire: wire,
                   asset: dexSign.HL_SPOT_ASSET_OFFSET + parseInt(pair.index, 10),
                   sz_decimals: parseInt(b.szDecimals, 10) || 0 };
      wireMap[wire] = key;
    }
    return { out: out, wireMap: wireMap };
  }
  function hlDexOfSymbol(sym) {
    const s = String(sym);
    if (s.indexOf(':') >= 0 && !dexSign.hlCoinIsSpot(s)) return s.split(':', 1)[0];
    return null;
  }
  async function hlEnsureProducts(route) {
    if (hlProds.futures && Date.now() - hlProds.ts < DEX_PRODUCTS_TTL_MS) return null;
    const rf = await hlInfo({ type: 'meta' }, route);
    if (!rf.ok) return rf.message;
    const rs = await hlInfo({ type: 'spotMeta' }, route);
    if (!rs.ok) return rs.message;
    hlProds.futures = hlParsePerps(rf.data);
    const sp = hlParseSpot(rs.data);
    hlProds.spot = sp.out;
    hlProds.wireMap = sp.wireMap;
    hlProds.ts = Date.now();
    return null;
  }
  async function hlSpec(market, symbol, route) {
    const dex = market === 'futures' ? hlDexOfSymbol(symbol) : null;
    if (dex) {
      const bc = hlBuilders[dex];
      if (bc && Date.now() - bc.ts < DEX_PRODUCTS_TTL_MS && bc.specs[symbol]) {
        return { ok: true, spec: bc.specs[symbol] };
      }
      const rd = await hlInfo({ type: 'perpDexs' }, route);
      if (!rd.ok) return { ok: false, message: rd.message };
      let dexIndex = -1;
      const lst = Array.isArray(rd.data) ? rd.data : [];
      for (let i = 0; i < lst.length; i++) {
        if (lst[i] && String(lst[i].name) === dex) { dexIndex = i; break; }
      }
      if (dexIndex < 0) return { ok: false, message: 'Unknown Hyperliquid symbol: ' + symbol };
      const rm = await hlInfo({ type: 'meta', dex: dex }, route);
      if (!rm.ok) return { ok: false, message: rm.message };
      const specs = hlParseBuilderPerps(rm.data, dex, dexIndex);
      hlBuilders[dex] = { ts: Date.now(), specs: specs };
      const spec = specs[symbol];
      if (!spec) return { ok: false, message: 'Unknown Hyperliquid symbol: ' + symbol };
      return { ok: true, spec: spec };
    }
    const err = await hlEnsureProducts(route);
    if (err) return { ok: false, message: err };
    const m = market === 'spot' ? hlProds.spot : hlProds.futures;
    let spec = m[symbol];
    if (!spec) {
      const low = String(symbol).toLowerCase();
      for (const k in m) { if (k.toLowerCase() === low) { spec = m[k]; break; } }
    }
    if (!spec) return { ok: false, message: 'Unknown Hyperliquid symbol: ' + symbol };
    return { ok: true, spec: spec };
  }
  async function hlMid(wireCoin, route) {
    // No snapshot cache on the desktop — one order, one fresh mids read.
    const dex = hlDexOfSymbol(wireCoin);
    const body = dex ? { type: 'allMids', dex: dex } : { type: 'allMids' };
    const r = await hlInfo(body, route);
    if (!r.ok) return null;
    const px = (r.data || {})[wireCoin];
    const n = Number(px);
    return (px != null && isFinite(n) && n > 0) ? String(px) : null;
  }
  async function hlMidNow(wireCoin, route) {
    // #2048 ORDER-CRITICAL allMids read — a market order needs its price
    // bound NOW. Rides the /exchange lane: NEVER queued behind the budgeter
    // tiers (rapid order flow debits the shared bucket dry, which starved
    // the very mid read the next market order needed — field log: 40s /info
    // hole, "No Hyperliquid price" failed closes). Debit-only spend + the
    // shared 429 latch stay; weight 2 is negligible. One paced 300ms retry:
    // a close gesture must not die on a single transient read.
    const dex = hlDexOfSymbol(wireCoin);
    const body = dex ? { type: 'allMids', dex: dex } : { type: 'allMids' };
    for (let a = 0; a < 2; a++) {
      if (a) await new Promise((res) => setTimeout(res, 300));
      try { hlBudgetSpend(_hlBudget, hlInfoWeight('allMids'), Date.now()); _hlBudgetPump(); } catch (e) {}
      let r;
      try {
        r = await httpJson(HL_HOST, 'POST', '/info', '', JSON.stringify(body), {}, route,
                           8 * 1024 * 1024);
      } catch (e) { continue; }
      if (r.status === 429) { hlBudget429(_hlBudget, Date.now(), 0); continue; }
      hlBudgetOk(_hlBudget);
      if (r.status !== 200) continue;
      let data;
      try { data = JSON.parse(r.text); } catch (e) { continue; }
      const px = (data || {})[wireCoin];
      const n = Number(px);
      if (px != null && isFinite(n) && n > 0) return String(px);
    }
    return null;
  }
  async function hlOpenRowsRaw(creds, dex, route) {
    const body = { type: 'frontendOpenOrders', user: String(creds.key).trim() };
    if (dex) body.dex = dex;
    const r = await hlInfo(body, route);
    if (!r.ok) return r;
    return { ok: true, rows: Array.isArray(r.data) ? r.data : [] };
  }
  async function hlPositions(creds, dex, route) {
    const body = { type: 'clearinghouseState', user: String(creds.key).trim() };
    if (dex) body.dex = dex;
    const r = await hlInfo(body, route);
    if (!r.ok) return r;
    const rows = [];
    for (const ap of ((r.data || {}).assetPositions) || []) {
      const p = (ap || {}).position || {};
      const szi = Number(p.szi);
      if (!isFinite(szi) || szi === 0) continue;
      let mark = null;
      const pv = Number(p.positionValue);
      if (isFinite(pv) && Math.abs(szi) > 0) mark = String(pv / Math.abs(szi));
      rows.push({ symbol: String(p.coin || ''),
                  side: szi > 0 ? 'buy' : 'sell',
                  size: String(Math.abs(szi)),
                  mark: mark });
    }
    return { ok: true, rows: rows };
  }
  async function hlPlace(creds, route, market, symbol, side, ordType, qty, price, clOrdID, flags) {
    const f = flags || {};
    const sr = await hlSpec(market, symbol, route);
    if (!sr.ok) return sr;
    const spec = sr.spec;
    const t = String(ordType).toLowerCase();
    let mid = null;
    const needMid = t === 'market';
    if (needMid) {
      // #2048: prefer the panel-supplied live book mid (fresh ≤2s — the DOM
      // already streams the traded symbol's book); otherwise the order-
      // critical direct read (hlMidNow) — NEVER the queued hlInfo path.
      mid = hlMidHintFresh(f.midHint, f.midTs, Date.now());
      if (!mid) mid = await hlMidNow(spec.wire, route);
      if (!mid) return { ok: false, message: 'No Hyperliquid price for the market order bound' };
    }
    let plan;
    try {
      plan = dexSign.hlOrderPlan({
        spec: spec, market: market, symbol: symbol, side: side, ordType: t,
        qty: qty, price: price, trigger: f.trigger, clOrdID: clOrdID,
        reduceOnly: !!f.reduceOnly, closeOnTrigger: !!f.closeOnTrigger,
        closePosition: !!f.closePosition, mid: mid,
      });
    } catch (e) { return { ok: false, message: (e && e.message) || 'bad order' }; }
    const r = await hlExchange(creds, plan.action, route);
    if (!r.ok) return r;
    const st = r.st || {};
    const oid = String(((st.resting || {}).oid != null ? st.resting.oid
                        : (st.filled || {}).oid) || '');
    return { ok: true, orderID: oid || null, clOrdID: clOrdID };
  }
  async function hlCancelBatch(creds, rows, route) {
    // Cancel a set of raw open-order rows in ONE /exchange action (engine
    // parity: asset ids resolved per row's wire coin).
    const cancels = [];
    for (const o of rows) {
      const coin = String((o || {}).coin || '');
      const market = dexSign.hlCoinIsSpot(coin) ? 'spot' : 'futures';
      const sym = market === 'spot' ? ((hlProds.wireMap || {})[coin] || coin) : coin;
      const sr = await hlSpec(market, sym, route);
      if (!sr.ok || o.oid == null) continue;
      cancels.push({ a: parseInt(sr.spec.asset, 10), o: parseInt(o.oid, 10) });
    }
    if (!cancels.length) return { ok: true, count: 0 };
    const r = await hlExchange(creds, { type: 'cancel', cancels: cancels }, route);
    if (!r.ok) return r;
    return { ok: true, count: cancels.length };
  }
  async function execHyperliquid(creds, intent, route) {
    const market = intent.market === 'spot' ? 'spot' : 'futures';
    if (intent.op === 'order') {
      return hlPlace(creds, route, market, intent.symbol, intent.side, intent.type,
                     intent.qty, intent.price, intent.clOrdID,
                     { reduceOnly: !!intent.reduceOnly, trigger: intent.trigger,
                       midHint: intent.midHint, midTs: intent.midTs });
    }
    if (intent.op === 'cancel') {
      const sr = await hlSpec(market, intent.symbol, route);
      if (!sr.ok) return sr;
      const action = dexSign.hlCancelAction(sr.spec.asset, intent.orderID);
      const r = await hlExchange(creds, action, route);
      if (!r.ok) return r;
      return { ok: true, cancelled: intent.orderID };
    }
    if (intent.op === 'cancel_all') {
      // Sweep working limits AND trigger orders on this symbol (DOM rule).
      const sr = await hlSpec(market, intent.symbol, route);
      if (!sr.ok) return sr;
      const wire = String(sr.spec.wire);
      const rr = await hlOpenRowsRaw(creds, hlDexOfSymbol(wire), route);
      if (!rr.ok) return rr;
      const mine = rr.rows.filter((o) => String((o || {}).coin || '') === wire);
      const rc = await hlCancelBatch(creds, mine, route);
      if (!rc.ok) return rc;
      // count: how many orders the sweep actually found — 0 while the board
      // still shows badges is the "wrong account address" honesty signal
      return { ok: true, cancelled: 'all', count: rc.count };
    }
    // close / sltp — fresh position read (builder symbols read THEIR dex).
    const dex = hlDexOfSymbol(intent.symbol);
    const pr = await findPosRetry(() => hlPositions(creds, dex, route), intent.symbol);
    if (!pr.ok) return pr;
    if (intent.op === 'close') {
      if (!pr.pos) return { ok: false, message: 'Position not found' };
      const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
      const r = await hlPlace(creds, route, 'futures', pr.pos.symbol, side, 'market',
                              pr.pos.size, null, intent.clOrdID,
                              { reduceOnly: true,
                                midHint: intent.midHint, midTs: intent.midTs });
      if (!r.ok) return r;
      return { ok: true, orderID: r.orderID, clOrdID: intent.clOrdID };
    }
    // sltp
    if (!pr.pos) return { ok: false, message: 'No open position to protect' };
    const terr = sltpTriggerOk(intent.kind, pr.pos.side, intent.trigger, pr.pos.mark);
    if (terr) return { ok: false, message: terr };
    const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
    const ordType = intent.kind === 'sl' ? 'stop' : 'tp_market';
    const r = await hlPlace(creds, route, 'futures', pr.pos.symbol, side, ordType,
                            pr.pos.size, null, intent.clOrdID,
                            { reduceOnly: true, trigger: intent.trigger,
                              closeOnTrigger: true });
    if (!r.ok) return r;
    return { ok: true, kind: intent.kind, orderID: r.orderID, clOrdID: intent.clOrdID };
  }

  // --- AsterDex (Binance-family; EIP-712 signed params in the QUERY) ----------
  // (method, Binance path) → Aster path; unlisted paths pass through.
  const ASTER_PATHS = {
    'GET /fapi/v2/positionRisk': '/fapi/v3/positionRisk',
    'GET /fapi/v2/balance': '/fapi/v3/balance',
    'GET /fapi/v1/openOrders': '/fapi/v3/openOrders',
    'POST /fapi/v1/order': '/fapi/v3/order',
    'DELETE /fapi/v1/order': '/fapi/v3/order',
    'DELETE /fapi/v1/allOpenOrders': '/fapi/v3/allOpenOrders',
    'GET /fapi/v1/positionSide/dual': '/fapi/v3/positionSide/dual',
    'POST /fapi/v1/positionSide/dual': '/fapi/v3/positionSide/dual',
    'DELETE /api/v3/openOrders': '/api/v3/allOpenOrders',
  };
  async function asterRequest(creds, method, market, reqPath, params, route) {
    // Creds slots: key = user wallet address, secret = API signer private
    // key, pass = signer address (mirrors the engine's 3-slot blob).
    reqPath = ASTER_PATHS[method + ' ' + reqPath] || reqPath;
    // Aster's signed nonce IS a wall-clock µs timestamp (Binance-family
    // recvWindow discipline applies) — feed it the offset-corrected clock.
    const offMs = await ensureVenueTime('asterdex', market, route);
    let parts;
    try {
      parts = dexSign.asterSignParams(creds.key, creds.pass, creds.secret, params || [],
                                      dexSign.asterNextNonce(Math.round((Date.now() + offMs) * 1000)));
    } catch (e) {
      return { ok: false, message: 'Aster signing failed: ' + ((e && e.message) || 'error') };
    }
    const query = dexSign.urlencodePy(parts);
    let r;
    try {
      r = await httpJson(market === 'futures' ? ASTER_FUT_HOST : ASTER_SPOT_HOST,
                         method, reqPath, query, null, {}, route);
    } catch (e) { return transportFail(e, 'Aster'); }
    if (r.status === 429 || r.status === 418) {
      return { ok: false, message: 'Rate limited by Aster — retry shortly', code: null };
    }
    let data = null;
    try { data = JSON.parse(r.text); } catch (e) { data = null; }
    const code = (data && typeof data.code === 'number') ? data.code : null;
    if (r.status >= 400 || (code != null && code < 0)) {
      const msg = code != null ? binanceErrorMessage(code, String((data && data.msg) || ''))
                               : 'Aster returned HTTP ' + r.status;
      return { ok: false, message: msg, code: code };
    }
    const unreadable = unreadableBodyMsg('Aster', r.status, data);
    if (unreadable) return { ok: false, message: unreadable, code: null };
    return { ok: true, data: data, code: code };
  }
  const asterOneway = {};
  async function ensureAsterOneWay(creds, route) {
    const c = asterOneway[creds.key];
    const now = Date.now();
    if (c && now - c.ts < ONEWAY_TTL_MS) return c.ok ? null : c.err;
    const r = await asterRequest(creds, 'GET', 'futures', '/fapi/v1/positionSide/dual', [], route);
    if (!r.ok) return r.message;
    if (r.data && r.data.dualSidePosition) {
      const r2 = await asterRequest(creds, 'POST', 'futures', '/fapi/v1/positionSide/dual',
                                    [['dualSidePosition', 'false']], route);
      if (!r2.ok && r2.code !== -4059) {   // -4059 = "no need to change"
        const err = 'Aster account is in hedge mode and could not be switched '
                  + 'to one-way (close hedge positions first): ' + r2.message;
        asterOneway[creds.key] = { ts: now, ok: false, err: err };
        return err;
      }
    }
    asterOneway[creds.key] = { ts: now, ok: true, err: '' };
    return null;
  }
  async function asterPlace(creds, route, market, symbol, side, ordType, qty, price, clOrdID, flags) {
    if (market === 'futures') {
      const err = await ensureAsterOneWay(creds, route);
      if (err) return { ok: false, message: err };
    }
    // NO Algo Order API on Aster: conditionals ride the plain order endpoint
    // (STOP_MARKET / STOP / TAKE_PROFIT_MARKET with stopPrice, engine parity).
    const params = dexSign.asterOrderParams(market, symbol, side, ordType, qty,
                                            price, clOrdID, flags || {});
    const reqPath = market === 'futures' ? '/fapi/v1/order' : '/api/v3/order';
    const r = await asterRequest(creds, 'POST', market, reqPath, params, route);
    if (!r.ok) return r;
    const oid = String((r.data || {}).orderId || '');
    return { ok: true, orderID: oid || null, clOrdID: clOrdID };
  }
  async function execAster(creds, intent, route) {
    const market = intent.market === 'spot' ? 'spot' : 'futures';
    const fetchPos = async () => {
      // Explicit symbol (Binance-family): the symbol-less list grows with
      // the venue's catalog and can blow past the httpJson byte cap.
      const r = await asterRequest(creds, 'GET', 'futures', '/fapi/v2/positionRisk',
                                   [['symbol', String(intent.symbol)]], route);
      if (!r.ok) return r;
      return { ok: true, rows: binancePositionRows(r.data) };
    };
    if (intent.op === 'order') {
      return asterPlace(creds, route, market, intent.symbol, intent.side, intent.type,
                        intent.qty, intent.price, intent.clOrdID,
                        { reduceOnly: !!intent.reduceOnly, trigger: intent.trigger });
    }
    if (intent.op === 'cancel') {
      const reqPath = market === 'futures' ? '/fapi/v1/order' : '/api/v3/order';
      const r = await asterRequest(creds, 'DELETE', market, reqPath,
                                   [['symbol', intent.symbol], ['orderId', intent.orderID]], route);
      if (!r.ok) return r;
      return { ok: true, cancelled: intent.orderID };
    }
    if (intent.op === 'cancel_all') {
      // ONE bulk call each side — Aster has no algo sweep (no Algo API).
      const reqPath = market === 'futures' ? '/fapi/v1/allOpenOrders' : '/api/v3/openOrders';
      const r = await asterRequest(creds, 'DELETE', market, reqPath,
                                   [['symbol', intent.symbol]], route);
      if (!r.ok && !(market === 'spot' && r.code === -2011)) return r;
      return { ok: true, cancelled: 'all' };
    }
    const pr = await findPosRetry(fetchPos, intent.symbol);
    if (!pr.ok) return pr;
    if (intent.op === 'close') {
      if (!pr.pos) return { ok: false, message: 'Position not found' };
      const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
      const r = await asterPlace(creds, route, 'futures', pr.pos.symbol, side, 'market',
                                 pr.pos.size, null, intent.clOrdID, { reduceOnly: true });
      if (!r.ok) return r;
      return { ok: true, orderID: r.orderID, clOrdID: intent.clOrdID };
    }
    // sltp
    if (!pr.pos) return { ok: false, message: 'No open position to protect' };
    const terr = sltpTriggerOk(intent.kind, pr.pos.side, intent.trigger, pr.pos.mark);
    if (terr) return { ok: false, message: terr };
    const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
    const ordType = intent.kind === 'sl' ? 'stop' : 'tp_market';
    const r = await asterPlace(creds, route, 'futures', pr.pos.symbol, side, ordType,
                               pr.pos.size, null, intent.clOrdID,
                               { reduceOnly: true, trigger: intent.trigger, closePosition: true });
    if (!r.ok) return r;
    return { ok: true, kind: intent.kind, orderID: r.orderID, clOrdID: intent.clOrdID };
  }

  // --- Arcus (perp DEX — Ed25519-signed writes, futures-only) -----------------
  async function arcRequest(method, reqPath, addr, bodyStr, headers, route) {
    let r;
    try {
      r = await httpJson(ARCUS_HOST, method, reqPath,
                         addr ? formEnc([['address', addr]]) : '',
                         bodyStr, headers || {}, route);
    } catch (e) { return transportFail(e, 'Arcus'); }
    if (r.status === 429) return { ok: false, message: 'Rate limited by Arcus — retry shortly' };
    let data = null;
    try { data = r.text ? JSON.parse(r.text) : {}; } catch (e) { data = null; }
    if (r.status >= 400) {
      return { ok: false, message: dexSign.arcusErrorMessage(data, r.status), status: r.status };
    }
    return { ok: true, data: data, status: r.status };
  }
  // {marketDisplayName: spec} incl. mark — refreshed when the mark is stale
  // (market orders derive their protective bound from it, engine parity).
  const arcProds = { ts: 0, specs: null };
  async function arcEnsureProducts(route, maxAgeMs) {
    if (arcProds.specs && Date.now() - arcProds.ts < maxAgeMs) return null;
    const r = await arcRequest('GET', '/v1/markets', null, null, {}, route);
    if (!r.ok) return r.message;
    const rows = (r.data && r.data.markets) || (Array.isArray(r.data) ? r.data : []);
    const out = {};
    for (const m of Array.isArray(rows) ? rows : []) {
      if (String((m || {}).status || '') !== 'ONLINE') continue;
      const sym = String(m.marketDisplayName || '');
      if (!sym || m.marketId == null) continue;
      out[sym] = { symbol: sym, market_id: parseInt(m.marketId, 10),
                   tick: m.tickSize != null ? String(m.tickSize) : null,
                   qty_step: m.stepSize != null ? String(m.stepSize) : null,
                   mark: m.markPrice != null ? String(m.markPrice) : null };
    }
    if (!Object.keys(out).length) return 'Arcus market list unavailable';
    arcProds.specs = out;
    arcProds.ts = Date.now();
    return null;
  }
  async function arcSpec(symbol, route, freshMark) {
    const err = await arcEnsureProducts(route, freshMark ? ARCUS_MARK_MAX_AGE_MS
                                                         : DEX_PRODUCTS_TTL_MS);
    if (freshMark && err) {
      // A stale mark must never bound a market order — fail loud.
      if (arcProds.specs && arcProds.specs[symbol]) {
        return { ok: false, message: 'Arcus mark price is stale (refresh failed) — '
                                     + 'market order rejected; retry shortly' };
      }
      return { ok: false, message: err };
    }
    if (err && !arcProds.specs) return { ok: false, message: err };
    const spec = (arcProds.specs || {})[symbol];
    if (!spec || spec.market_id == null) {
      return { ok: false, message: 'Unknown Arcus market ' + symbol };
    }
    return { ok: true, spec: spec };
  }
  function arcCreds(creds) {
    // key = master eth address, secret = '64-hex-ed25519-seed[:accountIndex]'
    const parsed = dexSign.arcusParseCreds(creds.secret);
    return { address: String(creds.key).trim(), seedHex: parsed[0], idx: parsed[1] };
  }
  async function arcPlace(c, route, symbol, side, ordType, qty, price, clOrdID, flags) {
    const f = flags || {};
    const t = String(ordType).toLowerCase();
    if (t !== 'limit' && t !== 'market') {
      return { ok: false, message: 'Stop orders are not supported on Arcus' };
    }
    const isMarket = t === 'market';
    const sr = await arcSpec(symbol, route, isMarket);
    if (!sr.ok) return sr;
    const spec = sr.spec;
    let px = price;
    if (isMarket) {
      try { px = dexSign.arcusMarketBoundPrice(spec.mark, spec.tick, side); }
      catch (e) {
        return { ok: false, message: 'Arcus mark price unavailable — cannot bound the market order' };
      }
    }
    let bp;
    try {
      bp = dexSign.arcusPlaceBodies(c.address, c.idx, spec, side, ordType,
                                    String(qty), String(px), clOrdID,
                                    { reduceOnly: !!(f.reduceOnly || f.closePosition) });
    } catch (e) {
      return { ok: false, message: 'Invalid order parameters: ' + ((e && e.message) || 'error') };
    }
    const headers = {
      'X-API-Key': dexSign.arcusPubkeyHex(c.seedHex),
      'X-Timestamp': String(bp.payload.ct),
      'X-Signature': dexSign.arcusSignPayload(c.seedHex, bp.payload),
    };
    const r = await arcRequest('POST', '/v1/placeOrder', c.address,
                               dexSign.arcusJson(bp.body), headers, route);
    if (!r.ok) return r;
    const d = (r.data && typeof r.data === 'object') ? r.data : {};
    return { ok: true, orderID: String(d.orderId || '') || null, clOrdID: clOrdID };
  }
  async function arcPositions(c, route) {
    const headers = { 'X-API-Key': dexSign.arcusPubkeyHex(c.seedHex) };
    const r = await arcRequest('GET', '/v1/positions', c.address, null, headers, route);
    if (!r.ok) {
      if (r.status === 404) return { ok: true, rows: [] };  // no activity yet
      return r;
    }
    const err = await arcEnsureProducts(route, DEX_PRODUCTS_TTL_MS);
    if (err && !arcProds.specs) return { ok: false, message: err };
    let raw = r.data;
    if (raw && !Array.isArray(raw)) raw = raw.positions || [];
    const rows = [];
    for (const p of Array.isArray(raw) ? raw : []) {
      const sym = String((p || {}).marketDisplayName || '');
      const spec = (arcProds.specs || {})[sym];
      const rawSz = Number(p.size);
      if (!sym || !isFinite(rawSz) || rawSz === 0) continue;
      // size arrives as an engine-native RAW integer → human via × step.
      let size = String(Math.abs(rawSz));
      if (spec && spec.qty_step) {
        try {
          const units = BigInt(String(Math.abs(rawSz)));
          const stepD = dexSign.arcusToUnits('1', spec.qty_step);   // 1/step
          size = (Number(units) / Number(stepD)).toString();
        } catch (e) { /* keep raw */ }
      }
      const sideS = String(p.side || '').toUpperCase();
      rows.push({ symbol: sym,
                  side: (sideS === 'LONG' || (!sideS && rawSz > 0)) ? 'buy' : 'sell',
                  size: size,
                  mark: p.markPx != null ? String(p.markPx)
                        : (p.markPrice != null ? String(p.markPrice) : null) });
    }
    return { ok: true, rows: rows };
  }
  async function execArcus(creds, intent, route) {
    if (intent.market === 'spot') return { ok: false, message: 'Arcus supports futures only' };
    let c;
    try { c = arcCreds(creds); } catch (e) {
      return { ok: false, message: (e && e.message) || 'bad Arcus credentials' };
    }
    if (intent.op === 'order') {
      return arcPlace(c, route, intent.symbol, intent.side, intent.type,
                      intent.qty, intent.price, intent.clOrdID,
                      { reduceOnly: !!intent.reduceOnly, trigger: intent.trigger });
    }
    if (intent.op === 'cancel') {
      const sr = await arcSpec(intent.symbol, route, false);
      if (!sr.ok) return sr;
      const bp = dexSign.arcusCancelBodies(c.address, c.idx, sr.spec.market_id, intent.orderID);
      const headers = {
        'X-API-Key': dexSign.arcusPubkeyHex(c.seedHex),
        'X-Timestamp': String(bp.payload.ct),
        'X-Signature': dexSign.arcusSignPayload(c.seedHex, bp.payload),
      };
      const r = await arcRequest('POST', '/v1/cancelOrder', c.address,
                                 dexSign.arcusJson(bp.body), headers, route);
      if (!r.ok) return r;
      return { ok: true, cancelled: intent.orderID };
    }
    if (intent.op === 'cancel_all') {
      // POST /v1/cancelAllOrders (scheme-2 signing: ts+action+JSON).
      const sr = await arcSpec(intent.symbol, route, false);
      if (!sr.ok) return sr;
      const ts = dexSign.arcusTsNs();
      const body = { address: c.address, accountIndex: c.idx,
                     marketId: sr.spec.market_id };
      const headers = {
        'X-API-Key': dexSign.arcusPubkeyHex(c.seedHex),
        'X-Timestamp': String(ts),
        'X-Signature': dexSign.arcusSignAction(c.seedHex, ts, 'cancelAllOrders', body),
      };
      const r = await arcRequest('POST', '/v1/cancelAllOrders', c.address,
                                 dexSign.arcusJson(body), headers, route);
      if (!r.ok) return r;
      return { ok: true, cancelled: 'all' };
    }
    if (intent.op === 'sltp') {
      return { ok: false, message: 'Stop orders are not supported on Arcus' };
    }
    // close — reduce-only market for the position's full size.
    const pr = await findPosRetry(() => arcPositions(c, route), intent.symbol);
    if (!pr.ok) return pr;
    if (!pr.pos) return { ok: false, message: 'Position not found' };
    const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
    const r = await arcPlace(c, route, pr.pos.symbol, side, 'market',
                             pr.pos.size, null, intent.clOrdID, { reduceOnly: true });
    if (!r.ok) return r;
    return { ok: true, orderID: r.orderID, clOrdID: intent.clOrdID };
  }

  // --- Lighter native trading (WASM zk signer) -----------------------------
  // Signing rides assets/lighter_signer.wasm (Go, poseidon/schnorr) — parity
  // proven against the Python SDK (identical txHash + payload). All REST here
  // is public except accountActiveOrders (auth token, signed offline).
  let _ltWasm = null;      // load promise (reset on failure so retry works)
  const _ltCli = { key: '' };                    // creds triple registered in the wasm
  const _ltAuth = { key: '', token: '', exp: 0 };
  const _ltNonce = { key: '', next: null, chain: Promise.resolve() };
  const _ltProds = { ts: 0, map: null };

  function ltWasmLoad() {
    if (_ltWasm) return _ltWasm;
    _ltWasm = (async () => {
      if (typeof globalThis.Go !== 'function') {
        require(path.join(__dirname, 'assets', 'wasm_exec.js'));
      }
      const buf = fs.readFileSync(path.join(__dirname, 'assets', 'lighter_signer.wasm'));
      const go = new globalThis.Go();
      const inst = await WebAssembly.instantiate(buf, go.importObject);
      go.run(inst.instance);   // registers the Sign* globals then parks on a channel
      const t0 = Date.now();
      while (typeof globalThis.CreateClient !== 'function') {
        if (Date.now() - t0 > 5000) throw new Error('Lighter signer WASM failed to initialize');
        await new Promise((r) => setTimeout(r, 25));
      }
      return true;
    })();
    _ltWasm.catch(() => { _ltWasm = null; });
    return _ltWasm;
  }

  // The Go wasm runtime reads walltime via the JS Date — shift it by the
  // probed venue offset for the duration of one SYNC sign call so the tx
  // ExpiredAt / order expiry stamps ride venue time, not the raw PC clock
  // (native-venue clock-sync rule).
  function ltWithClock(offMs, fn) {
    const off = Number(offMs) || 0;
    if (!off) return fn();
    const RealDate = globalThis.Date;
    const Shifted = class extends RealDate {
      constructor(...a) { if (a.length === 0) { super(RealDate.now() + off); } else { super(...a); } }
      static now() { return RealDate.now() + off; }
    };
    globalThis.Date = Shifted;
    try { return fn(); } finally { globalThis.Date = RealDate; }
  }

  // Ensure the wasm client holds THIS creds triple (idempotent re-register on
  // creds change). Returns {ok, acct, kidx} or an honest failure.
  async function ltClient(creds) {
    const p = ltParseKey(creds.key);
    if (!p) return { ok: false, message: 'Invalid Lighter key — use accountIndex or accountIndex:apiKeyIndex' };
    const pk = String(creds.secret || '').trim();
    if (!/^(0x)?[0-9a-fA-F]{80}$/.test(pk)) {
      return { ok: false, message: 'Invalid Lighter API private key (expect 40-byte hex)' };
    }
    try { await ltWasmLoad(); } catch (e) {
      return { ok: false, message: (e && e.message) || 'Lighter signer load failed' };
    }
    const ck = p.acct + ':' + p.kidx + ':' + pk.slice(-8);
    if (_ltCli.key !== ck) {
      let r;
      try {
        r = globalThis.CreateClient('https://' + LIGHTER_HOST, pk, LIGHTER_CHAIN_ID, p.kidx, p.acct);
      } catch (e) {
        return { ok: false, message: 'Lighter signer rejected the key: ' + ((e && e.message) || 'error') };
      }
      if (r && r.error) return { ok: false, message: 'Lighter signer rejected the key: ' + r.error };
      _ltCli.key = ck;
      _ltAuth.key = '';                          // creds changed → new token
      _ltNonce.key = ''; _ltNonce.next = null;   // and a fresh nonce fetch
    }
    return { ok: true, acct: p.acct, kidx: p.kidx };
  }

  // Perp catalog (public /orderBookDetails), 10-min cache — engine parity
  // fields: market_id + price/size_decimals.
  async function ltSpec(symbol, route) {
    if (!_ltProds.map || Date.now() - _ltProds.ts > PRODUCTS_TTL_MS) {
      let r;
      try {
        r = await httpJson(LIGHTER_HOST, 'GET', '/api/v1/orderBookDetails', '', null, {}, route, 8 * 1024 * 1024);
      } catch (e) {
        return { ok: false, message: 'Lighter catalog fetch failed: ' + ((e && e.message) || 'error') };
      }
      let rows = null;
      try { rows = JSON.parse(r.text).order_book_details; } catch (e) { rows = null; }
      if (!Array.isArray(rows)) {
        return { ok: false, message: 'Lighter catalog unavailable (HTTP ' + (r.status || 0) + ')' };
      }
      const map = {};
      for (const d of rows) {
        const sym = String((d && d.symbol) || '');
        if (!sym) continue;
        if (d.market_type != null && String(d.market_type) !== 'perp') continue;
        if (d.status != null && String(d.status) !== 'active') continue;
        const pd = d.price_decimals != null ? Number(d.price_decimals) : Number(d.supported_price_decimals);
        const sd = d.size_decimals != null ? Number(d.size_decimals) : Number(d.supported_size_decimals);
        const mid = Number(d.market_id);
        if (!Number.isInteger(pd) || !Number.isInteger(sd) || !Number.isInteger(mid)) continue;
        map[sym.toLowerCase()] = { mid: mid, pd: pd, sd: sd, symbol: sym };
      }
      _ltProds.map = map; _ltProds.ts = Date.now();
    }
    const s = _ltProds.map[String(symbol || '').toLowerCase()];
    return s ? { ok: true, spec: s } : { ok: false, message: 'Unknown Lighter symbol ' + symbol };
  }

  // Auth token for the one authenticated read (accountActiveOrders). Signed
  // OFFLINE by the wasm; ~6h deadline, refreshed 10 min early.
  function ltAuthToken(cc) {
    const k = cc.acct + ':' + cc.kidx;
    if (_ltAuth.key === k && Date.now() < _ltAuth.exp - 600000) return { ok: true, token: _ltAuth.token };
    const deadline = Math.floor(Date.now() / 1000) + 6 * 3600;
    let r;
    try { r = globalThis.CreateAuthToken(deadline, cc.kidx, cc.acct); } catch (e) {
      return { ok: false, message: 'Lighter auth token failed: ' + ((e && e.message) || 'error') };
    }
    const tok = r && (r.authToken || r.token);
    if (!tok || (r && r.error)) {
      return { ok: false, message: 'Lighter auth token failed: ' + ((r && r.error) || 'no token') };
    }
    _ltAuth.key = k; _ltAuth.token = String(tok); _ltAuth.exp = deadline * 1000;
    return { ok: true, token: _ltAuth.token };
  }

  // Sign + send ONE tx under the nonce chain (engine _tx parity): nonce
  // advances only on an ACCEPTED send; ANY failure drops the cache (hard
  // /nextNonce refresh next tx). signFn(nonce) → wasm result {txType, txInfo,
  // txHash?, error?}.
  function ltTx(cc, route, signFn) {
    const nk = cc.acct + ':' + cc.kidx;
    const run = _ltNonce.chain.then(async () => {
      const drop = () => { _ltNonce.key = ''; _ltNonce.next = null; };
      try {
        let nonce = (_ltNonce.key === nk) ? _ltNonce.next : null;
        if (nonce == null) {
          const r = await httpJson(LIGHTER_HOST, 'GET', '/api/v1/nextNonce',
            'account_index=' + cc.acct + '&api_key_index=' + cc.kidx, null, {}, route);
          let n = null;
          try { n = Number(JSON.parse(r.text).nonce); } catch (e) { n = null; }
          if (!Number.isSafeInteger(n)) {
            return { ok: false, message: 'Lighter nonce fetch failed (HTTP ' + (r.status || 0) + ')' };
          }
          nonce = n;
        }
        const off = await ensureVenueTime('lighter', null, route);
        let s;
        try { s = ltWithClock(off, () => signFn(nonce)); } catch (e) {
          drop();
          return { ok: false, message: 'Lighter signing failed: ' + ((e && e.message) || 'error') };
        }
        if (!s || s.error || !s.txInfo) {
          drop();
          return { ok: false, message: 'Lighter signing failed: ' + ((s && s.error) || 'empty result') };
        }
        const body = 'tx_type=' + encodeURIComponent(String(s.txType)) +
                     '&tx_info=' + encodeURIComponent(String(s.txInfo));
        const r = await httpJson(LIGHTER_HOST, 'POST', '/api/v1/sendTx', '', body,
                                 { 'Content-Type': 'application/x-www-form-urlencoded' }, route);
        let data = null;
        try { data = JSON.parse(r.text); } catch (e) { data = null; }
        const code = data && data.code != null ? Number(data.code) : null;
        if (r.status === 200 && (code === null || code === 0 || code === 200)) {
          _ltNonce.key = nk; _ltNonce.next = nonce + 1;
          return { ok: true, data: data };
        }
        drop();
        const msg = (data && (data.message || data.msg)) || '';
        return { ok: false, message: 'Lighter error ' + (code != null ? code : ('HTTP ' + (r.status || 0))) + (msg ? ' — ' + msg : '') };
      } catch (e) {
        drop();
        const em = (e && e.message) || 'error';
        if (em === 'proxy-unavailable') return { ok: false, message: 'Proxy is enabled but unavailable' };
        return { ok: false, message: 'Lighter request failed: ' + em };
      }
    });
    _ltNonce.chain = run.then(() => {}, () => {});
    return run;
  }

  // Top-of-book ±2% execution bound for market/IOC orders — book fetch
  // failure FAILS the order (engine parity, no unbounded markets).
  async function ltBook(mid, side, pd, route) {
    let r;
    try {
      r = await httpJson(LIGHTER_HOST, 'GET', '/api/v1/orderBookOrders',
                         'market_id=' + mid + '&limit=1', null, {}, route);
    } catch (e) {
      return { ok: false, message: 'Lighter order book unavailable — market order not sent' };
    }
    let d = null;
    try { d = JSON.parse(r.text); } catch (e) { d = null; }
    const buy = !String(side || '').toLowerCase().startsWith('s');
    const rows = (d && d[buy ? 'asks' : 'bids']) || [];
    const px = rows.length ? ltUnits(String(rows[0].price), pd) : null;
    const pu = ltBoundUnits(px, buy);
    if (!pu) return { ok: false, message: 'Lighter order book unavailable — market order not sent' };
    return { ok: true, pu: pu };
  }

  // Open positions from the PUBLIC /account blob (engine parity: sign<0 =
  // Sell, size = |position|; no mark in this blob).
  async function ltPositions(cc, route) {
    let r;
    try {
      r = await httpJson(LIGHTER_HOST, 'GET', '/api/v1/account',
                         'by=index&value=' + cc.acct, null, {}, route, 4 * 1024 * 1024);
    } catch (e) {
      return { ok: false, message: 'Lighter account fetch failed: ' + ((e && e.message) || 'error') };
    }
    let d = null;
    try { d = JSON.parse(r.text); } catch (e) { d = null; }
    const acc = d && Array.isArray(d.accounts) && d.accounts[0];
    if (!acc) return { ok: false, message: 'Lighter account fetch failed (HTTP ' + (r.status || 0) + ')' };
    const rows = [];
    for (const p of (acc.positions || [])) {
      const sz = Number(p && p.position);
      if (!isFinite(sz) || sz === 0) continue;
      rows.push({
        symbol: String(p.symbol || ''),
        side: Number(p.sign || 1) < 0 ? 'sell' : 'buy',
        size: String(p.position).replace(/^-/, ''),
        mark: null,
      });
    }
    return { ok: true, rows: rows };
  }

  // Place one perp order — EXACT engine mapping: limit→type0/GTT/exp-1,
  // market→1/IOC/exp0 + book bound, stop→2 / tp_market→4 (IOC, px =
  // trigger∓2%), stop_limit→3/GTT. Wasm stamps expiry itself for exp=-1.
  async function ltPlace(cc, route, symbol, side, type, qty, price, clOrdID, opts) {
    const sr = await ltSpec(symbol, route);
    if (!sr.ok) return sr;
    const sp = sr.spec;
    const bu = ltUnits(qty, sp.sd);
    if (!bu || bu <= 0) return { ok: false, message: 'Quantity below one step' };
    const isAsk = String(side || '').toLowerCase().startsWith('s');
    const t = String(type || '').toLowerCase();
    const isStop = (t === 'stop' || t === 'stop_limit' || t === 'tp_market');
    let otype, tif, exp = -1, trigU = 0, pu = null;
    if (isStop) {
      trigU = ltUnits(opts.trigger, sp.pd);
      if (!trigU || trigU <= 0) return { ok: false, message: 'Invalid trigger price' };
      if (t === 'stop_limit') {
        otype = 3; tif = 1;                       // STOP_LOSS_LIMIT / GTT
        if (price == null) return { ok: false, message: 'Missing limit price' };
        pu = ltUnits(price, sp.pd);
        if (!pu || pu <= 0) return { ok: false, message: 'Invalid price' };
      } else {
        otype = (t === 'tp_market') ? 4 : 2;      // TAKE_PROFIT / STOP_LOSS
        tif = 0;                                  // IOC after trigger
        pu = ltBoundUnits(trigU, !isAsk);         // ±2% around the trigger
        if (!pu) return { ok: false, message: 'Invalid trigger price' };
      }
    } else if (t === 'market') {
      otype = 1; tif = 0; exp = 0;                // MARKET / IOC
      const b = await ltBook(sp.mid, side, sp.pd, route);
      if (!b.ok) return b;
      pu = b.pu;
    } else {
      otype = 0; tif = 1;                         // LIMIT / GTT
      if (price == null) return { ok: false, message: 'Missing limit price' };
      pu = ltUnits(price, sp.pd);
      if (!pu || pu <= 0) return { ok: false, message: 'Invalid price' };
    }
    const coi = ltCoi(clOrdID);
    const ro = opts.reduceOnly ? 1 : 0;
    const r = await ltTx(cc, route, (nonce) =>
      globalThis.SignCreateOrder(sp.mid, coi, bu, pu, isAsk ? 1 : 0, otype, tif,
                                 ro, trigU, exp, 0, 0, 0, 0, 0, 0,
                                 nonce, cc.kidx, cc.acct));
    if (!r.ok) return r;
    // Synthetic id namespace mirrors the engine: ltc:/lts: + client index.
    return { ok: true, orderID: (isStop ? 'lts:' : 'ltc:') + coi, clOrdID: clOrdID || null };
  }

  async function execLighter(creds, intent, route) {
    if (intent.market === 'spot') {
      return { ok: false, message: 'Lighter spot trading is not supported yet (watch-only)' };
    }
    const cc = await ltClient(creds);
    if (!cc.ok) return cc;
    if (intent.op === 'order') {
      return ltPlace(cc, route, intent.symbol, intent.side, intent.type,
                     intent.qty, intent.price, intent.clOrdID,
                     { reduceOnly: !!intent.reduceOnly, trigger: intent.trigger });
    }
    if (intent.op === 'cancel') {
      const sr = await ltSpec(intent.symbol, route);
      if (!sr.ok) return sr;
      const mid = sr.spec.mid;
      const oid = String(intent.orderID || '');
      let oidx = null;
      if (/^lt[cs]:\d+$/.test(oid)) {
        // Synthetic id → resolve client_order_index → live order_index via
        // the authenticated active-orders read. order_index is int64: pull
        // its DIGITS from the raw body (JSON.parse would round >2^53) and
        // fail honestly if it exceeds the JS/wasm float boundary.
        const coi = Number(oid.slice(4));
        const at = ltAuthToken(cc);
        if (!at.ok) return at;
        let r;
        try {
          r = await httpJson(LIGHTER_HOST, 'GET', '/api/v1/accountActiveOrders',
                             'account_index=' + cc.acct + '&market_id=' + mid +
                             '&auth=' + encodeURIComponent(at.token),
                             null, {}, route, 4 * 1024 * 1024);
        } catch (e) {
          return { ok: false, message: 'Lighter open-orders fetch failed: ' + ((e && e.message) || 'error') };
        }
        const rx = new RegExp('\\{[^{}]*"client_order_index"\\s*:\\s*"?' + coi + '"?[^{}]*\\}');
        const m = (r.text || '').match(rx);
        const im = m && m[0].match(/"order_index"\s*:\s*"?(\d+)/);
        if (!im) {
          return { ok: false, message: 'Order not found on Lighter (already filled or cancelled?)' };
        }
        oidx = Number(im[1]);
        if (!Number.isSafeInteger(oidx)) {
          return { ok: false, message: 'Lighter order index exceeds the native signer range — cancel via Server trading' };
        }
      } else {
        oidx = Number(oid);
        if (!Number.isSafeInteger(oidx) || oidx < 0) return { ok: false, message: 'Bad order id' };
      }
      const r = await ltTx(cc, route, (nonce) =>
        globalThis.SignCancelOrder(mid, oidx, 0, nonce, cc.kidx, cc.acct));
      if (!r.ok) return r;
      return { ok: true, cancelled: oid, orderID: oid };
    }
    if (intent.op === 'cancel_all') {
      // One book-wide cancel-all tx (sweeps stops too). Count honesty: the
      // venue doesn't report how many — count stays null.
      const sr = await ltSpec(intent.symbol, route);
      if (!sr.ok) return sr;
      const r = await ltTx(cc, route, (nonce) =>
        globalThis.SignCancelAllOrders(0, 0, sr.spec.mid, 0, nonce, cc.kidx, cc.acct));
      if (!r.ok) return r;
      return { ok: true, cancelled: 'all', count: null };
    }
    if (intent.op === 'sltp') {
      const pr = await findPosRetry(() => ltPositions(cc, route), intent.symbol);
      if (!pr.ok) return pr;
      if (!pr.pos) return { ok: false, message: 'No open position to protect' };
      const terr = sltpTriggerOk(intent.kind, pr.pos.side, intent.trigger, pr.pos.mark);
      if (terr) return { ok: false, message: terr };
      const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
      const ordType = intent.kind === 'sl' ? 'stop' : 'tp_market';
      const r = await ltPlace(cc, route, pr.pos.symbol, side, ordType, pr.pos.size,
                              null, intent.clOrdID, { reduceOnly: true, trigger: intent.trigger });
      if (!r.ok) return r;
      return { ok: true, orderID: r.orderID, clOrdID: intent.clOrdID };
    }
    // close — reduce-only market for the position's full size.
    const pr = await findPosRetry(() => ltPositions(cc, route), intent.symbol);
    if (!pr.ok) return pr;
    if (!pr.pos) return { ok: false, message: 'Position not found' };
    const side = String(pr.pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
    const r = await ltPlace(cc, route, pr.pos.symbol, side, 'market', pr.pos.size,
                            null, intent.clOrdID, { reduceOnly: true });
    if (!r.ok) return r;
    return { ok: true, orderID: r.orderID, clOrdID: intent.clOrdID };
  }

  // One intent → executed result (renderer-facing shape mirrors the engine).
  // Native ACCOUNT-DATA read (#1701): positions / open orders / balances via
  // this device's stored creds — read-only signed GETs, no order path. Raw
  // venue rows go back to the renderer, whose pure builders map them into the
  // /terminal/state venue-section shape.
  // #1724: every acct_read rides the shared rate-limit guard + single-flight
  // (acctReadGuard above): cool-down short-circuit after a venue rate-limits,
  // one in-flight request train per venue+account shared across all boards
  // AND windows (this main process is the single funnel), short result memo.
  const execAcctRead = acctReadGuard(execAcctReadRaw, Date.now,
    (ev, info) => tdiag('acct', ev, info));
  async function execAcctReadRaw(intent) {
    if (intent.venue === 'binance') return await execBinanceAcctRead(intent);
    if (intent.venue === 'phemex') return await execPhemexAcctRead(intent);
    if (intent.venue === 'okx') return await execOkxAcctRead(intent);
    if (intent.venue === 'gate') return await execGateAcctRead(intent);
    if (intent.venue === 'bitget') return await execBitgetAcctRead(intent);
    if (intent.venue === 'mexc') return await execMexcAcctRead(intent);
    if (intent.venue === 'kucoin') return await execKucoinAcctRead(intent);
    if (intent.venue === 'bitmex') return await execBitmexAcctRead(intent);
    if (intent.venue === 'asterdex') return await execAsterdexAcctRead(intent);
    if (intent.venue === 'kraken') return await execKrakenAcctRead(intent);
    if (intent.venue !== 'bybit') return { ok: false, message: 'native account reads not supported for this venue' };
    const creds = credsGet(intent.credSlot || intent.venue);
    if (!creds) return { ok: false, message: 'No API key on this device — provision Native trading first' };
    const route = routeNorm(intent.route);
    // #2051: acct reads keep the private push socket warm (push-driven
    // display) — no-op while the loop already runs.
    try { bybPushEnsure(intent.credSlot || 'bybit', creds, route); } catch (e) { /* REST path */ }
    const bal = await bybRequest(creds, 'GET', '/v5/account/wallet-balance',
                                 [['accountType', 'UNIFIED']], null, route);
    if (!bal.ok) return bal;
    const pos = await bybRequest(creds, 'GET', '/v5/position/list',
                                 [['category', 'linear'], ['settleCoin', 'USDT'], ['limit', '200']], null, route);
    if (!pos.ok) return pos;
    const fo = await bybRequest(creds, 'GET', '/v5/order/realtime',
                                [['category', 'linear'], ['settleCoin', 'USDT'], ['limit', '50']], null, route);
    if (!fo.ok) return fo;
    const so = await bybRequest(creds, 'GET', '/v5/order/realtime',
                                [['category', 'spot'], ['limit', '50']], null, route);
    if (!so.ok) return so;
    const lst = (r) => (((r.data || {}).result) || {}).list || [];
    return { ok: true, balance: lst(bal), positions: lst(pos), futOrders: lst(fo), spotOrders: lst(so) };
  }

  // Binance native account read (#1714): signed HMAC GETs mirroring the
  // engine's BinanceAdapter REST builders — spot account (balances) + spot
  // open orders, futures positionRisk / openOrders (+ Algo conditionals) /
  // balance. Spot vs futures hosts differ (api. vs fapi.); every request
  // rides bnRequest (recvWindow + ensureVenueTime clock offset — raw
  // Date.now() regresses -1021) and the shared proxy agent cache. Raw venue
  // rows go back to the renderer (its pure twins shape them into the
  // ?binance=1 /state venue-section shape). NO geo special-casing (user
  // decision): a 451-blocked machine/proxy surfaces the normal fail-visible
  // error, never a silent server fallback.
  async function execBinanceAcctRead(intent) {
    const creds = credsGet(intent.credSlot || 'binance');
    if (!creds) return { ok: false, message: 'No API key on this device — provision Native trading first' };
    const route = routeNorm(intent.route);
    // #1943: acct reads keep the user-data streams warm (push-driven display)
    try { bnUdsEnsure(intent.credSlot || 'binance', creds, route); } catch (e) { /* REST-only */ }
    // #2192 leg isolation: spot and futures ride SEPARATE hosts and separate
    // clock offsets — a poisoned spot clock (-1021) must not blank the
    // futures rows (field 2026-08-14: one bad boot probe hid every position
    // for a whole session). Within one market the first failure short-
    // circuits that market's remaining legs (same signer + clock); a
    // rate-limited/banned leg still fails the WHOLE read so the acct guard
    // keeps its cool-down hints.
    const sa = await bnRequest(creds, 'GET', 'spot', '/api/v3/account',
                               [['omitZeroBalances', 'true']], route);
    const so = sa.ok
      ? await bnRequest(creds, 'GET', 'spot', '/api/v3/openOrders', [], route) : sa;
    const spotErr = !sa.ok ? sa : (!so.ok ? so : null);
    const fb = await bnRequest(creds, 'GET', 'futures', '/fapi/v2/balance', [], route);
    // Symbol-less positionRisk returns EVERY listed contract (200KB+) —
    // raise the httpJson byte cap so JSON.parse never sees a truncated body
    // (shell-httpjson convention; the engine twin parses the same payload).
    const pos = fb.ok
      ? await bnRequest(creds, 'GET', 'futures', '/fapi/v2/positionRisk',
                        [], route, 4 * 1024 * 1024) : fb;
    const fo = pos.ok
      ? await bnRequest(creds, 'GET', 'futures', '/fapi/v1/openOrders', [], route) : pos;
    const ao = fo.ok
      ? await bnRequest(creds, 'GET', 'futures', '/fapi/v1/openAlgoOrders', [], route) : fo;
    const futErr = !fb.ok ? fb : (!pos.ok ? pos : (!fo.ok ? fo : (!ao.ok ? ao : null)));
    const rl = (e) => e && (e.rateLimited || e.banned);
    if (rl(spotErr)) return spotErr;
    if (rl(futErr)) return futErr;
    if (spotErr && futErr) return spotErr;   // both markets dead — plain failure
    const arr = (r) => (Array.isArray(r.data) ? r.data : []);
    const out = { ok: true };
    if (!spotErr) { out.spotAcct = sa.data || {}; out.spotOrders = arr(so); }
    if (!futErr) {
      out.futBalance = arr(fb); out.positions = arr(pos);
      out.futOrders = arr(fo); out.algoOrders = arr(ao);
    }
    if (spotErr || futErr) {
      out.legErr = {};
      if (spotErr) out.legErr.spot = spotErr.message || 'spot read failed';
      if (futErr) out.legErr.futures = futErr.message || 'futures read failed';
      tdiag('acct', 'bn_leg_err', { leg: spotErr ? 'spot' : 'futures',
        m: String((spotErr || futErr).message || '').slice(0, 90) });
    }
    return out;
  }

  // Phemex native account read (#1713): signed GETs mirroring the engine's
  // REST builders — futures account+positions (accountPositions), open orders
  // BOTH markets (g-orders/activeList incl. its code-30000 per-symbol
  // fallback; /spot/orders), spot wallets. Raw venue rows go back to the
  // renderer (its pure twins shape them); the per-currency / per-spot-symbol
  // valueScale maps ride along from the products cache so the renderer can
  // descale the 1e8/e-scaled spot payloads without another fetch.
  async function execPhemexAcctRead(intent) {
    const creds = credsGet(intent.credSlot || 'phemex');
    if (!creds) return { ok: false, message: 'No API key on this device — provision Native trading first' };
    const route = routeNorm(intent.route);
    // #2281 read DEADLINE. This read is four-plus SEQUENTIAL signed legs, so at
    // the generic 12 s transport timeout one hung leg could hold Phemex's share
    // of the shared pool for most of a minute (observed max 16,828 ms). Every
    // leg's socket timeout is clamped to what is LEFT of the deadline, and the
    // optional per-symbol fallback loops stop at it, so the whole read is
    // bounded — a hung request is abandoned instead of wedging the venue.
    // Fail-visible: an abandoned leg surfaces as that leg's own error (or a
    // partial-error note where the read already degrades), never as silent
    // empty data. Only THIS lane is clamped: orders, cancels and the fills read
    // pass no timeoutMs and keep the full HTTP_TIMEOUT_MS budget.
    const dl0 = Date.now() + PHEMEX_ACCT_DEADLINE_MS;
    // No post-expiry floor: once dl0 has passed there is no budget left to
    // grant, so a leg must not START at all rather than be handed a courtesy
    // slice. Every wire call in this function goes through rd()/cat() so the
    // deadline is genuinely absolute across the whole read.
    const legMs = () => Math.min(PHEMEX_ACCT_LEG_MS, dl0 - Date.now());
    const past = () => Date.now() >= dl0;
    const timedOut = { ok: false, message: 'Phemex account read timed out' };
    const rd = (step) => past() ? Promise.resolve(timedOut)
      : signedRequest(creds, Object.assign({ timeoutMs: legMs(), deadlineAt: dl0 }, step), route);
    // The products catalog is a wire GET too (8 MB cap, generic timeout) and
    // was the last unbounded await in this lane. It is TTL-cached, so the
    // steady-state path resolves instantly and never races; only a cold or
    // expired catalog can lose, and losing degrades exactly like a catalog
    // fetch failure already does here (no derivable fallback symbols ⇒
    // surfaced partial-error note; no scales ⇒ renderer-side default of 8).
    const cat = async () => {
      const left = dl0 - Date.now();
      if (left <= 0) return null;
      const pr = phemexProducts(route);
      Promise.resolve(pr).catch(() => {});   // stray fetch — never unhandled
      let tm = null;
      const r = await Promise.race([
        Promise.resolve(pr).catch(() => null),
        new Promise((rs) => { tm = setTimeout(() => rs(null), left); }),
      ]);
      if (tm) clearTimeout(tm);
      return r || null;
    };
    const acct = await rd({
      method: 'GET', path: '/g-accounts/accountPositions',
      query: 'currency=USDT', body: null });
    if (!acct.ok) return acct;
    let fo = await rd({
      method: 'GET', path: '/g-orders/activeList',
      query: 'currency=USDT', body: null });
    let futRows;
    if (fo.ok) {
      futRows = (fo.data && fo.data.rows) || (Array.isArray(fo.data) ? fo.data : []);
    } else if (phemexSymbolRequired(fo)) {
      // Some deployments require a symbol (code 30000 OR 10500 — #1722) —
      // per-position symbols (engine twin).
      futRows = [];
      const poss = ((acct.data || {}).positions || []).slice(0, 10);
      for (const p of poss) {
        if (!p || !p.symbol) continue;
        if (past()) break;                      // #2281 deadline — stop walking symbols
        const rs = await rd({
          method: 'GET', path: '/g-orders/activeList',
          query: 'symbol=' + encodeURIComponent(p.symbol), body: null });
        if (rs.ok) futRows = futRows.concat((rs.data && rs.data.rows) || (Array.isArray(rs.data) ? rs.data : []));
      }
    } else return fo;
    // Wallets BEFORE spot orders (#1722): the spot symbol-required fallback
    // derives its symbols from nonzero wallets × the products catalog.
    const wl = await rd({
      method: 'GET', path: '/spot/wallets', query: '', body: null });
    if (!wl.ok) return wl;
    // Shape-tolerant: /spot/wallets data is a bare list today, but a wrapped
    // {rows:[…]} variant must not silently empty the spot holdings (the DOM
    // posrow derives from these rows — engine twin unwraps identically).
    const wallets = Array.isArray(wl.data) ? wl.data
      : (wl.data && Array.isArray(wl.data.rows)) ? wl.data.rows : [];
    const so = await rd({
      method: 'GET', path: '/spot/orders', query: '', body: null });
    let spotRows;
    const partialErrors = [];
    if (so.ok) {
      spotRows = (so.data && so.data.rows) || (Array.isArray(so.data) ? so.data : []);
    } else if (phemexSymbolRequired(so)) {
      // #1722: symbol-required family only — retry per-symbol (spot symbols
      // from nonzero wallets × products catalog, cap 10 like futures); no
      // derivable symbols → degrade like the server twin (empty spotOrders +
      // a surfaced partial-error note) instead of failing the whole read.
      // Auth/permission errors stay fail-closed via the else-return below.
      spotRows = [];
      let syms = [];
      try {
        const pr = await cat();   // #2281 deadline-bounded; null ⇒ no symbols
        if (!pr) throw new Error('catalog unavailable within read deadline');
        const curs = {};
        for (const w of wallets) {
          const nz = (Number(w && w.balanceEv) || 0)
                   + (Number(w && w.lockedTradingBalanceEv) || 0)
                   + (Number(w && w.lockedWithdrawEv) || 0)
                   + (Number(w && w.balanceRv) || 0);   // #1785 Rv-variant tolerance (engine twin)
          if (nz) curs[String(w.currency || '')] = 1;
        }
        for (const p of ((pr.raw && pr.raw.products) || [])) {
          if (p && String(p.type) === 'Spot' && p.symbol
              && curs[String(p.baseCurrency || '')]) syms.push(p.symbol);
        }
      } catch (e) { /* no catalog → no derivable symbols → degrade below */ }
      let got = false;
      for (const sym of syms.slice(0, 10)) {
        if (past()) break;                      // #2281 deadline — stop walking symbols
        const rs = await rd({
          method: 'GET', path: '/spot/orders',
          query: 'symbol=' + encodeURIComponent(sym), body: null });
        if (rs.ok) { got = true; spotRows = spotRows.concat((rs.data && rs.data.rows) || (Array.isArray(rs.data) ? rs.data : [])); }
      }
      if (!got) partialErrors.push({ scope: 'spot', message: so.message || 'spot orders unavailable' });
    } else return so;
    let curScales = {}, spotBaseScales = {};
    try {
      const pr = await cat();   // #2281 deadline-bounded (TTL-cached: normally instant)
      if (pr) {
        curScales = pr.curScales || {};
        for (const s in (pr.spot || {})) spotBaseScales[s] = pr.spot[s].value_scale;
      }
    } catch (e) { /* scales default to 8 renderer-side — majors byte-identical */ }
    const out = { ok: true,
             acct: acct.data || {},
             futOrders: futRows,
             spotOrders: spotRows,
             wallets: wallets,
             curScales: curScales, spotBaseScales: spotBaseScales };
    // additive — absent on clean reads so legacy payloads stay byte-identical
    if (partialErrors.length) out.partialErrors = partialErrors;
    return out;
  }

  // Phemex native fills read: signed /api-data trades GETs for a BOUNDED
  // caller-supplied symbol set (panel caps per market; re-capped here) — the
  // Your-trades archive source on device-key-only setups (the server engine
  // has no key to fetch with). RAW venue rows go back verbatim: the ENGINE
  // parses them with its own fetch_fills normalizers via /native_fills, so
  // there is exactly ONE parser truth and no fabricated fields. One page per
  // symbol (limit 200), never a pagination walk; own single-flight latch
  // (panel cadence is ≥20s — an overlapping call is a quiet no-op error).
  // Fail-visible: any failed leg fails the whole read so the panel never
  // half-advances its since-cursor.
  let _phFillsBusy = false;
  async function execPhemexFillsRead(intent) {
    const creds = credsGet(intent.credSlot || 'phemex');
    if (!creds) return { ok: false, message: 'No API key on this device — provision Native trading first' };
    if (_phFillsBusy) return { ok: false, message: 'fills read already in flight' };
    _phFillsBusy = true;
    try {
      const route = routeNorm(intent.route);
      const now = Date.now();
      let end = Math.floor(Number(intent.endMs) || 0);
      if (!(end > 0) || end > now + 60000) end = now;
      let start = Math.floor(Number(intent.startMs) || 0);
      if (!(start > 0) || start >= end) start = end - 24 * 3600 * 1000;
      if (end - start > 26 * 3600 * 1000) start = end - 26 * 3600 * 1000;
      const symsOf = (v) => (Array.isArray(v) ? v : []).map(String)
        .filter((s) => s && s.length <= 32 && /^[A-Za-z0-9]+$/.test(s)).slice(0, 6);
      const futures = {}, spot = {};
      for (const sym of symsOf(intent.futSymbols)) {
        const r = await signedRequest(creds, {
          method: 'GET', path: '/api-data/g-futures/trades',
          query: 'symbol=' + encodeURIComponent(sym) + '&start=' + start + '&end=' + end + '&limit=200',
          body: null }, route);
        if (!r.ok) return r;
        futures[sym] = (r.data && r.data.rows) || (Array.isArray(r.data) ? r.data : []);
      }
      for (const sym of symsOf(intent.spotSymbols)) {
        const r = await signedRequest(creds, {
          method: 'GET', path: '/api-data/spots/trades',
          query: 'symbol=' + encodeURIComponent(sym) + '&start=' + start + '&end=' + end + '&limit=200',
          body: null }, route);
        if (!r.ok) return r;
        spot[sym] = (r.data && r.data.rows) || (Array.isArray(r.data) ? r.data : []);
      }
      return { ok: true, futures: futures, spot: spot };
    } finally { _phFillsBusy = false; }
  }

  // OKX native account read (#1716): signed GETs mirroring OkxAdapter's REST
  // state seed — one /account/balance (spot wallets + the unified USDT that
  // backs the futures account), /account/positions?instType=SWAP, pending
  // plain orders BOTH markets (/trade/orders-pending), pending algo orders
  // (/trade/orders-algo-pending, trigger + conditional). Raw venue rows go
  // back verbatim — sz/pos are CONTRACTS, converted renderer-side via the
  // panel's OKX catalog ctVal (phemex-scales precedent; no shell-side ctVal
  // fetch so the payload can't drift from the boards' own contract sizes).
  // Fail-closed: any failed leg returns that leg's {ok:false,...}.
  async function execOkxAcctRead(intent) {
    const creds = credsGet(intent.credSlot || 'okx');
    if (!creds) return { ok: false, message: 'No API key on this device — provision Native trading first' };
    if (!creds.pass) return { ok: false, message: 'OKX API passphrase missing — re-provision Native trading on this device' };
    const route = routeNorm(intent.route);
    const bal = await okxRequest(creds, 'GET', '/api/v5/account/balance', null, null, route);
    if (!bal.ok) return bal;
    const pos = await okxRequest(creds, 'GET', '/api/v5/account/positions',
                                 [['instType', 'SWAP']], null, route);
    if (!pos.ok) return pos;
    // Cursor-walk the pending-order pages exactly like OkxAdapter._orders_pending.
    const walk = async (instType) => {
      const rows = [];
      let after = '';
      for (let page = 0; page < 10; page++) {
        const params = [['instType', instType], ['limit', '100']];
        if (after) params.push(['after', after]);
        const r = await okxRequest(creds, 'GET', '/api/v5/trade/orders-pending', params, null, route);
        if (!r.ok) return r;
        const lst = ((r.data || {}).data) || [];
        for (const o of lst) rows.push(o);
        if (lst.length < 100) break;
        after = String((lst[lst.length - 1] || {}).ordId || '');
        if (!after) break;
      }
      return { ok: true, rows: rows };
    };
    const fo = await walk('SWAP');
    if (!fo.ok) return fo;
    const so = await walk('SPOT');
    if (!so.ok) return so;
    // Pending algo (stop-family) orders: both types, SWAP rows only (engine
    // _algos_pending drops non-SWAP instType).
    const algos = [];
    for (const ot of ['trigger', 'conditional']) {
      let after = '';
      for (let page = 0; page < 10; page++) {
        const params = [['ordType', ot], ['limit', '100']];
        if (after) params.push(['after', after]);
        const r = await okxRequest(creds, 'GET', '/api/v5/trade/orders-algo-pending', params, null, route);
        if (!r.ok) return r;
        const lst = ((r.data || {}).data) || [];
        for (const o of lst) { if (String((o || {}).instType || 'SWAP') === 'SWAP') algos.push(o); }
        if (lst.length < 100) break;
        after = String((lst[lst.length - 1] || {}).algoId || '');
        if (!after) break;
      }
    }
    return { ok: true,
             balance: ((bal.data || {}).data) || [],
             positions: ((pos.data || {}).data) || [],
             futOrders: fo.rows, spotOrders: so.rows, algoOrders: algos };
  }

  // Gate native account read (#1716): signed GETs mirroring GateAdapter's
  // state seed. Futures size/left are SIGNED CONTRACTS → base via
  // quanto_multiplier renderer-side (panel Gate catalog ct_val). Unified
  // detection follows the gate-unified-detection rule: a POSITIVE
  // /unified/accounts balance is proof-positive of unified mode; a failed
  // mode read that the funds probe can't resolve surfaces as an error, never
  // a silent "classic" assumption. Fail-closed per leg.
  async function execGateAcctRead(intent) {
    const creds = credsGet(intent.credSlot || 'gate');
    if (!creds) return { ok: false, message: 'No API key on this device — provision Native trading first' };
    const route = routeNorm(intent.route);
    // #2153: acct reads keep the private push sockets warm (push-driven
    // display) — no-op while the loops already run. The read then RE-ATTACHES
    // push fills to the fresh snapshot panel-side (binance-shell-push rule).
    try { gatePushEnsure(intent.credSlot || 'gate', creds, route); } catch (e) { /* REST-only */ }
    const spotAcc = await gateRequest(creds, 'GET', '/spot/accounts', null, null, route);
    if (!spotAcc.ok) return spotAcc;
    const pos = await gateRequest(creds, 'GET', '/futures/usdt/positions', null, null, route);
    if (!pos.ok && String(pos.message || '').indexOf('futures account') < 0) return pos;
    // Classic futures wallet: a spot-only account 404s USER_NOT_FOUND — that
    // is a normal state (no futures account), not a fatal leg.
    const futAcc = await gateRequest(creds, 'GET', '/futures/usdt/accounts', null, null, route);
    if (!futAcc.ok && String(futAcc.message || '').indexOf('futures account') < 0) return futAcc;
    // Unified mode + funds. The mode read may 403 on keys lacking the
    // unified/account permission — carry mode + error, decide renderer-side.
    let unifiedMode = null, unifiedErr = null, unifiedAcc = null;
    const modeR = await gateRequest(creds, 'GET', '/unified/account_mode', null, null, route);
    if (modeR.ok && modeR.data && typeof modeR.data === 'object' && modeR.data.mode) {
      unifiedMode = String(modeR.data.mode) !== 'classic';
    } else {
      unifiedErr = (modeR.ok ? 'unified account_mode read failed'
                             : String(modeR.message || 'unified account_mode read failed'));
    }
    // Probe /unified/accounts whenever mode says unified, the classic wallet
    // is absent/zero, or the mode read failed (dust must not suppress it).
    let classicBal = 0;
    try { classicBal = Number((futAcc.data || {}).total) || 0; } catch (e) { classicBal = 0; }
    if (unifiedMode || !futAcc.ok || classicBal === 0 || unifiedErr) {
      const uni = await gateRequest(creds, 'GET', '/unified/accounts', null, null, route);
      if (uni.ok && uni.data && typeof uni.data === 'object') unifiedAcc = uni.data;
    }
    const spotOo = await gateRequest(creds, 'GET', '/spot/open_orders', null, null, route);
    if (!spotOo.ok) return spotOo;
    const futWalk = async (path) => {
      const rows = [];
      let offset = 0;
      for (let page = 0; page < 10; page++) {
        const r = await gateRequest(creds, 'GET', path,
                                    [['status', 'open'], ['limit', '100'], ['offset', String(offset)]],
                                    null, route);
        if (!r.ok) return r;
        const lst = Array.isArray(r.data) ? r.data : [];
        for (const o of lst) rows.push(o);
        if (lst.length < 100) break;
        offset += 100;
      }
      return { ok: true, rows: rows };
    };
    const fo = await futWalk('/futures/usdt/orders');
    if (!fo.ok) return fo;
    const po = await futWalk('/futures/usdt/price_orders');
    if (!po.ok) return po;
    return { ok: true,
             spotAccounts: Array.isArray(spotAcc.data) ? spotAcc.data : [],
             positions: (pos.ok && Array.isArray(pos.data)) ? pos.data : [],
             futAccount: futAcc.ok && futAcc.data && typeof futAcc.data === 'object' ? futAcc.data : null,
             unified: unifiedMode, unifiedAccount: unifiedAcc, unifiedError: unifiedErr,
             spotOrders: Array.isArray(spotOo.data) ? spotOo.data : [],
             futOrders: fo.rows, priceOrders: po.rows };
  }

  // ── Bitget device-local blotter live lane (#2246) ────────────────────────
  // Bitget has no shell-side private WS session yet (the push lane is the
  // follow-on task), so the local blotter's LIVE source is a paced REST
  // fills poll that feeds the SAME per-slot raw ring shape every push venue
  // uses. lbDrain consumes it through the normal incremental cursor /
  // exactly-once merge / journal / prune path — nothing downstream needs a
  // Bitget special case. The poll is single-flight and TTL-gated, and it is
  // driven ONLY by the lblot ops, so a slot that never uses the local
  // blotter pays no extra REST traffic at all.
  const BG_FILL_RING_CAP = 600;
  const BG_LIVE_TTL_MS = 1200;                 // ≥1 fetch per panel lblot beat
  const BG_LIVE_OVERLAP_MS = 90000;            // per-market re-ask window
  const BG_LIVE_COLD_MS = 15 * 60 * 1000;      // first poll of a session
  const BG_LIVE_PAGES = 4;                     // bounded — backfill owns depth
  const BG_PAGE_GAP_MS = 450;                  // HB_PAGE_GAP_MS twin (own scope)
  const BG_MAX_SPAN_MS = 89 * 86400 * 1000;    // venue refuses >90d (#2251)
  const bgFillRings = {};   // slot → { sp, fu, spTs, fuTs, t, busy }
  function bgFillRing(slot) {
    let R = bgFillRings[String(slot)];
    if (!R) {
      R = bgFillRings[String(slot)] = {
        sp: { rows: [], seen: {}, rev: 0 }, fu: { rows: [], seen: {}, rev: 0 },
        spTs: 0, fuTs: 0, t: 0, busy: null, tail: '',
      };
    }
    return R;
  }
  // Ring key is side-INCLUSIVE: a self-match returns TWO rows sharing one
  // tradeId (opposite sides) and a side-less key silently drops a leg,
  // leaving the trade stuck open (lbFillKey carries the same rule).
  function bgRingKey(f) {
    const eid = String((f && f.tradeId) || '');
    return eid ? eid + '|' + String((f && f.side) || '').toLowerCase() : '';
  }
  function bgFillPush(F, rows) {
    let n = 0;
    for (const f of (rows || [])) {
      const k = bgRingKey(f);
      if (!k || F.seen[k]) continue;
      F.seen[k] = 1;
      F.rows.push(f);
      lbSrcTouch(F);   // #2230 one touch per pushed row (drain cursor)
      n++;
    }
    if (F.rows.length > BG_FILL_RING_CAP) {
      const drop = F.rows.splice(0, F.rows.length - BG_FILL_RING_CAP);
      // evicted rows are far older than any re-ask window, so forgetting
      // their keys cannot resurrect them; the store-level dedupe is the
      // real exactly-once guard either way.
      for (const f of drop) { const k = bgRingKey(f); if (k) delete F.seen[k]; }
    }
    return n;
  }
  // ONE cursor walk for every Bitget fill consumer (live poll, backfill,
  // re-import): engine BitgetHistory._fills_walk twin. Mix nests rows under
  // data.fillList, spot returns a bare list; `idLessThan` pages OLDER on the
  // last row's tradeId. `full:true` = the page cap was hit with a full page
  // still pending — the caller decides whether that is a gap note or a hard
  // failure. Never throws.
  async function bgFillsWalk(creds, market, frm, to, route, maxPages, gapMs) {
    const rows = [];
    let after = '';
    let pages = 0;
    const cap = maxPages > 0 ? maxPages : 1;
    for (let page = 0; page < cap; page++) {
      const path = market === 'futures' ? '/api/v2/mix/order/fills'
                                        : '/api/v2/spot/trade/fills';
      const params = market === 'futures'
        ? [['productType', BITGET_PRODUCT_TYPE], ['startTime', String(Math.floor(frm))],
           ['endTime', String(Math.ceil(to))], ['limit', '100']]
        : [['startTime', String(Math.floor(frm))], ['endTime', String(Math.ceil(to))],
           ['limit', '100']];
      if (after) params.push(['idLessThan', after]);
      if (page && gapMs > 0) await new Promise((rs) => setTimeout(rs, gapMs));
      let r;
      try { r = await bitgetRequest(creds, 'GET', path, params, null, route); }
      catch (e) { r = { ok: false, message: (e && e.message) || 'Bitget fills fetch failed' }; }
      pages++;
      if (!r || !r.ok) {
        return { ok: false, rows: rows, full: false, pages: pages,
                 message: (r && r.message) || 'Bitget ' + market + ' fills fetch failed' };
      }
      const d = (r.data || {}).data;
      const lst = (d && !Array.isArray(d) && typeof d === 'object') ? d.fillList : d;
      const page_rows = Array.isArray(lst) ? lst.filter((x) => x && typeof x === 'object') : [];
      for (const f of page_rows) rows.push(f);
      if (page_rows.length < 100) return { ok: true, rows: rows, full: false, pages: pages };
      after = String((page_rows[page_rows.length - 1] || {}).tradeId || '');
      // A FULL page with no usable cursor is a truncation, not an end of
      // history — reporting it as complete is exactly how a partial history
      // gets activated. `full` is the honest verdict either way.
      if (!after) return { ok: true, rows: rows, full: true, pages: pages };
    }
    return { ok: true, rows: rows, full: true, pages: pages };   // cap hit
  }
  function bgFillTs(f) {
    // #2251 same seconds-stamp guard the normalizer applies: a seconds value
    // taken as ms sets the cursor to 1970, and the NEXT window then spans 56
    // years — which Bitget rejects outright, so the market silently returns
    // nothing for the rest of the session. Cursor and stored row must agree.
    return lbBgTsMs((f && (f.cTime || f.fillTime || f.uTime)) || 0);
  }
  // Paced live refresh for ONE Bitget slot. Single-flight + TTL-gated (N
  // windows polling the same slot in one beat cost ONE fetch). Best-effort
  // by design: a failed poll means no new rows this beat — the next beat and
  // the gap backfill recover. PER-MARKET high-water marks: one shared mark
  // would let a recent futures fill truncate the spot re-ask window.
  async function lbBgLive(venue, slot, route) {
    if (venue !== 'bitget') return;
    const R = bgFillRing(slot);
    if (R.busy) { try { await R.busy; } catch (e) {} return; }
    const now = Date.now();
    if ((now - (R.t || 0)) < BG_LIVE_TTL_MS) return;
    const creds = credsGet(slot);
    if (!creds || !creds.key || !creds.pass) return;
    R.t = now;
    const p = (async () => {
      for (const mk of ['spot', 'futures']) {
        const key = mk === 'spot' ? 'spTs' : 'fuTs';
        const F = mk === 'spot' ? R.sp : R.fu;
        let frm = R[key] > 0 ? Math.max(0, R[key] - BG_LIVE_OVERLAP_MS)
                             : now - BG_LIVE_COLD_MS;
        // #2251 window sanity: Bitget refuses a span wider than 90 days, so
        // ONE bad cursor (a seconds stamp read as ms, a cleared mark) made
        // every later poll of that market fail and the ring never filled
        // again. Clamp instead of asking for an impossible window.
        frm = Math.min(Math.max(frm, now - BG_MAX_SPAN_MS), now);
        const w = await bgFillsWalk(creds, mk, frm, now + 1000, routeNorm(route),
                                    BG_LIVE_PAGES, BG_PAGE_GAP_MS);
        if (!w.ok) continue;                   // best-effort — next beat retries
        bgFillPush(F, w.rows);
        let hwm = R[key] || 0;
        for (const f of w.rows) { const t = bgFillTs(f); if (t > hwm) hwm = t; }
        R[key] = hwm > 0 ? hwm : Math.max(R[key] || 0, now - BG_LIVE_OVERLAP_MS);
      }
    })();
    R.busy = p;
    try { await p; } catch (e) { /* best-effort */ }
    if (R.busy === p) R.busy = null;
  }
  // Recent normalized live rows for the panel's fill chime / spot cost basis
  // (the chart triangles read the local STORE). Read-only view of the ring —
  // costs no REST call, so the account read stays exactly as expensive as
  // before for slots that never touch the local blotter.
  const BG_LIVE_SHARE_N = 200;
  function bgLiveFills(slot) {
    const R = bgFillRings[String(slot)];
    if (!R) return [];
    const out = [];
    for (const f of R.sp.rows) { const n = lbNormBitgetFill(f, 'spot'); if (n) out.push(n); }
    for (const f of R.fu.rows) { const n = lbNormBitgetFill(f, 'futures'); if (n) out.push(n); }
    out.sort((a, b) => (a.ts || 0) - (b.ts || 0));
    return out.length > BG_LIVE_SHARE_N ? out.slice(out.length - BG_LIVE_SHARE_N) : out;
  }

  // Bitget native account read (#1716): signed GETs mirroring BitgetAdapter's
  // state seed. Spot + futures are SEPARATE accounts (no unified pool).
  // Futures sizes are plain BASE coin (no multiplier). Fail-closed per leg.
  async function execBitgetAcctRead(intent) {
    const creds = credsGet(intent.credSlot || 'bitget');
    if (!creds) return { ok: false, message: 'No API key on this device — provision Native trading first' };
    if (!creds.pass) return { ok: false, message: 'Bitget API passphrase missing — re-provision Native trading on this device' };
    const route = routeNorm(intent.route);
    // #2247: acct reads keep the private push socket warm (push-driven
    // display) — no-op while the loop already runs. The read then RE-ATTACHES
    // push fills to the fresh snapshot panel-side (binance-shell-push rule).
    try { bgPushEnsure(intent.credSlot || 'bitget', creds, route); } catch (e) { /* REST-only */ }
    // #2251 pump the LIVE fill lane on the account beat. Before this the
    // ring was refreshed only from lblot_read / lblot_trades, i.e. during
    // backfill and while the trades panel was open — so a normal trading
    // session recorded NOTHING: every acct read answered lbFills: 0 and no
    // fill ever reached the local store. The account read is the one beat
    // that always runs, so it is the honest place to drive it.
    // Gated on intent.lblot (panel sends it only while the local blotter is
    // ACTIVE for Bitget), started in PARALLEL with the account legs and
    // awaited just before the reply: a slot that never uses the local
    // blotter still pays exactly zero extra REST calls, and one that does
    // pays no extra wall-clock. lbBgLive keeps its own single-flight + TTL,
    // so N windows on one slot still cost ONE fetch per beat.
    const lbPump = intent.lblot
      ? lbBgLive('bitget', intent.credSlot || 'bitget', route).catch(() => {})
      : null;
    const pt = BITGET_PRODUCT_TYPE;
    const spotAssets = await bitgetRequest(creds, 'GET', '/api/v2/spot/account/assets', null, null, route);
    if (!spotAssets.ok) return spotAssets;
    const futAcc = await bitgetRequest(creds, 'GET', '/api/v2/mix/account/accounts',
                                       [['productType', pt]], null, route);
    if (!futAcc.ok) return futAcc;
    const pos = await bitgetRequest(creds, 'GET', '/api/v2/mix/position/all-position',
                                    [['productType', pt], ['marginCoin', 'USDT']], null, route);
    if (!pos.ok) return pos;
    const dl = (r) => {
      const d = (r.data || {}).data;
      if (Array.isArray(d)) return d;
      // mix pending/plan endpoints nest rows under data.entrustedList.
      if (d && typeof d === 'object' && Array.isArray(d.entrustedList)) return d.entrustedList;
      return [];
    };
    // idLessThan cursor-walk (engine _orders_pending / _plans_pending parity).
    const walk = async (path, base) => {
      const rows = [];
      let after = '';
      for (let page = 0; page < 10; page++) {
        const params = base.concat([['limit', '100']]);
        if (after) params.push(['idLessThan', after]);
        const r = await bitgetRequest(creds, 'GET', path, params, null, route);
        if (!r.ok) return r;
        const lst = dl(r);
        for (const o of lst) rows.push(o);
        if (lst.length < 100) break;
        after = String((lst[lst.length - 1] || {}).orderId || '');
        if (!after) break;
      }
      return { ok: true, rows: rows };
    };
    const fo = await walk('/api/v2/mix/order/orders-pending', [['productType', pt]]);
    if (!fo.ok) return fo;
    const plans = [];
    for (const planType of ['normal_plan', 'profit_loss']) {
      const p = await walk('/api/v2/mix/order/orders-plan-pending', [['productType', pt], ['planType', planType]]);
      if (!p.ok) return p;
      for (const o of p.rows) plans.push(o);
    }
    const so = await walk('/api/v2/spot/trade/unfilled-orders', []);
    if (!so.ok) return so;
    // #2246 additive: recent LOCAL fills for this credential slot (empty
    // unless the local blotter poll has warmed the ring for this slot). The
    // panel only reads it while the local blotter is ACTIVE for Bitget —
    // capability alone must never suppress the server fills.
    if (lbPump) await lbPump;   // #2251 fills polled alongside the acct legs
    return { ok: true,
             spotAssets: dl(spotAssets), futAccounts: dl(futAcc), positions: dl(pos),
             futOrders: fo.rows, planOrders: plans, spotOrders: so.rows,
             lbFills: bgLiveFills(intent.credSlot || 'bitget') };
  }

  // MEXC native account read (#1716): TWO hosts — spot api.mexc.com
  // (Binance-style HMAC) and futures contract.mexc.com (ApiKey/Request-Time/
  // Signature); mxRequest routes by `market`. Futures vol is CONTRACTS →
  // base via contractSize renderer-side (panel MEXC catalog ctVal). Spot
  // /api/v3/openOrders is SYMBOL-REQUIRED: try the bare call, else a bounded
  // balance-derived <CCY>USDT symbol walk (engine _spot_open_orders parity;
  // restricted symbols may 400 — best-effort, never fatal). Fail-closed on
  // the futures legs; spot walk tolerates per-symbol failures.
  async function execMexcAcctRead(intent) {
    const creds = credsGet(intent.credSlot || 'mexc');
    if (!creds) return { ok: false, message: 'No API key on this device — provision Native trading first' };
    const route = routeNorm(intent.route);
    const spotAcc = await mxRequest(creds, 'GET', 'spot', '/api/v3/account', null, null, route);
    if (!spotAcc.ok) return spotAcc;
    const futAsset = await mxRequest(creds, 'GET', 'futures',
                                     '/api/v1/private/account/asset/USDT', null, null, route);
    if (!futAsset.ok) return futAsset;
    const pos = await mxRequest(creds, 'GET', 'futures',
                                '/api/v1/private/position/open_positions', null, null, route);
    if (!pos.ok) return pos;
    const futWalk = async (path, extra) => {
      const rows = [];
      for (let page = 1; page <= 10; page++) {
        const params = [['page_num', String(page)], ['page_size', '100']].concat(extra || []);
        const r = await mxRequest(creds, 'GET', 'futures', path, params, null, route);
        if (!r.ok) return r;
        const lst = Array.isArray((r.data || {}).data) ? r.data.data : [];
        for (const o of lst) rows.push(o);
        if (lst.length < 100) break;
      }
      return { ok: true, rows: rows };
    };
    const fo = await futWalk('/api/v1/private/order/list/open_orders', null);
    if (!fo.ok) return fo;
    const plan = await futWalk('/api/v1/private/planorder/list/orders', [['states', '1']]);
    if (!plan.ok) return plan;
    // Spot open orders: symbol-required — bare call first, then the hint walk.
    let spotOrders = [];
    const bareSo = await mxRequest(creds, 'GET', 'spot', '/api/v3/openOrders', null, null, route);
    if (bareSo.ok && Array.isArray(bareSo.data)) {
      spotOrders = bareSo.data;
    } else {
      const syms = [];
      for (const b of ((spotAcc.data || {}).balances) || []) {
        const ccy = String((b || {}).asset || '');
        if (ccy && ccy !== 'USDT' && ccy !== 'USDC') syms.push(ccy + 'USDT');
        if (syms.length >= 10) break;
      }
      for (const sym of syms) {
        const r = await mxRequest(creds, 'GET', 'spot', '/api/v3/openOrders',
                                  [['symbol', sym]], null, route);
        if (r.ok && Array.isArray(r.data)) spotOrders = spotOrders.concat(r.data);
      }
    }
    return { ok: true,
             spotBalances: ((spotAcc.data || {}).balances) || [],
             futAsset: (futAsset.data || {}).data || null,
             positions: ((pos.data || {}).data) || [],
             futOrders: fo.rows, planOrders: plan.rows, spotOrders: spotOrders };
  }

  // --- #2272 KuCoin local-blotter live lane --------------------------------
  // The RECORDING half of the fill lane (the private-WS `match` delta owns
  // EMISSION — see kcFillLaneOwns). It is the fee-bearing lane: /api/v1/fills
  // rows carry the venue's own `fee`, so every row that reaches the ring has
  // a real fee and an unknown fee is never stored as a real zero. Same paced
  // shape as every other REST live lane — single-flight, TTL-gated, driven
  // ONLY by the lblot ops and the push catch-up, so a slot that never touches
  // the local blotter pays no extra REST traffic at all.
  //
  // TWO HOSTS, TWO CLOCKS: the path is identical on both, but the high-water
  // marks are strictly per market. One shared mark would let a futures fill
  // (stamped by the futures host's clock, and delivered in NANOSECONDS)
  // truncate the spot re-ask window against a clock that never produced it.
  const KC_FILL_RING_CAP = 600;
  const KC_LIVE_TTL_MS = 1200;                 // ≥1 fetch per panel lblot beat
  const KC_LIVE_OVERLAP_MS = 90000;            // per-market re-ask window
  const KC_LIVE_COLD_MS = 15 * 60 * 1000;      // first poll of a session
  const KC_LIVE_PAGES = 4;                     // bounded — backfill owns depth
  const KC_PAGE_GAP_MS = 450;
  const KC_PAGE_SIZE = 100;
  const kcFillRings = {};   // slot → { sp, fu, spTs, fuTs, t, busy }
  function kcFillRingFor(slot) {
    let R = kcFillRings[String(slot)];
    if (!R) {
      R = kcFillRings[String(slot)] = {
        sp: { rows: [], seen: {}, rev: 0 }, fu: { rows: [], seen: {}, rev: 0 },
        spTs: 0, fuTs: 0, t: 0, busy: null, route: null,
      };
    }
    return R;
  }
  // Side-INCLUSIVE, like every other venue ring: a self-match returns TWO
  // rows sharing one tradeId (opposite sides) and a side-less key silently
  // drops a leg, leaving the trade stuck open (lbFillKey carries the rule).
  function kcRingKey(f) {
    const eid = String((f && f.tradeId) || '');
    return eid ? eid + '|' + String((f && f.side) || '').toLowerCase() : '';
  }
  function kcFillPush(F, rows, fresh) {
    let n = 0;
    for (const f of (rows || [])) {
      const k = kcRingKey(f);
      if (!k || F.seen[k]) continue;
      // Fee UNKNOWN is not fee zero. /api/v1/fills always carries `fee`, so
      // this never fires in practice — and when it somehow does, the row is
      // left UNSEEN so the next overlap window re-asks for it rather than
      // recording a real zero the break-even replay would then trust.
      if (!lbKcFeeKnown(f)) { F.nofee = (F.nofee | 0) + 1; continue; }
      F.seen[k] = 1;
      F.rows.push(f);
      if (fresh) fresh.push(f);
      lbSrcTouch(F);   // one touch per pushed row (drain cursor)
      n++;
    }
    if (F.rows.length > KC_FILL_RING_CAP) {
      const drop = F.rows.splice(0, F.rows.length - KC_FILL_RING_CAP);
      for (const f of drop) { const k = kcRingKey(f); if (k) delete F.seen[k]; }
    }
    return n;
  }
  // #2272 the fee-bearing half of the push lane. The WS `match` delta pushed
  // its fid the instant the execution streamed; these are the SAME executions
  // re-read from REST with the venue's own fee and realized PnL, normalized
  // into the row shape the panel's fill/BE replay consumes. Same fid ⇒ the
  // chime already latched, so this beat repaints the posrow and the chart
  // triangle without ringing twice. A futures row whose contract multiplier
  // is still cold is SKIPPED here (never sized at a guessed 1:1) — the acct
  // read's lbFills share carries it once kcMult landed.
  function kcPushFillRows(slot, mk, rows) {
    if (!rows || !rows.length || !pushLedgerCb) return;
    const sess = kcPushSessions[String(slot || 'kucoin')];
    if (!sess || sess.closed) return;
    const sc = mk === 'spot' ? sess.sp : sess.fu;
    if (!sc || !sc._pk) return;
    let n = 0;
    for (const f of rows) {
      let nrm = null;
      if (mk === 'spot') nrm = lbNormKucoinFill(f, 'spot', null);
      else {
        const mc = kcMultCache[String((f && f.symbol) || '')];
        if (!(Number(mc && mc.v) > 0)) continue;
        nrm = lbNormKucoinFill(f, 'futures', mc.v);
      }
      if (!nrm) continue;
      krLseq(sc);
      kcPushSc(sc, 'fill', kcFillFid(f), nrm);
      n++;
    }
    if (n && mk === 'futures') { krLseq(sc); kcPushSc(sc, 'pos'); }
  }
  // ONE cursor walk for every KuCoin fill consumer (live poll, backfill,
  // re-import): KucoinHistory._fills_walk twin — currentPage pagination over
  // a startAt/endAt window, same path on both hosts. `full:true` = the page
  // cap was hit with pages still pending; the caller decides whether that is
  // a gap note or a hard failure. Never throws.
  async function kcFillsWalk(creds, market, frm, to, route, maxPages, gapMs) {
    const rows = [];
    let pages = 0;
    const cap = maxPages > 0 ? maxPages : 1;
    for (let page = 1; page <= cap; page++) {
      const params = [['startAt', String(Math.floor(frm))], ['endAt', String(Math.ceil(to))],
                      ['currentPage', String(page)], ['pageSize', String(KC_PAGE_SIZE)]];
      if (page > 1 && gapMs > 0) await new Promise((rs) => setTimeout(rs, gapMs));
      let r;
      try { r = await kcRequest(creds, 'GET', market, '/api/v1/fills', params, null, route); }
      catch (e) { r = { ok: false, message: (e && e.message) || 'KuCoin fills fetch failed' }; }
      pages++;
      if (!r || !r.ok) {
        return { ok: false, rows: rows, full: false, pages: pages,
                 message: (r && r.message) || 'KuCoin ' + market + ' fills fetch failed' };
      }
      const d = (r.data || {}).data || {};
      const lst = Array.isArray(d.items) ? d.items : [];
      const pageRows = lst.filter((x) => x && typeof x === 'object');
      for (const f of pageRows) rows.push(f);
      const total = Number(d.totalPage) | 0;
      if (!pageRows.length || (total > 0 && page >= total)) {
        return { ok: true, rows: rows, full: false, pages: pages };
      }
      if (total <= 0 && pageRows.length < KC_PAGE_SIZE) {
        return { ok: true, rows: rows, full: false, pages: pages };
      }
    }
    return { ok: true, rows: rows, full: true, pages: pages };   // cap hit
  }
  // Paced live refresh for ONE KuCoin slot. `only` restricts the walk to one
  // market AND bypasses the TTL — that is the push lane's fee catch-up, which
  // must land the just-streamed execution now, not on the next panel beat.
  async function lbKcLive(venue, slot, route, only) {
    if (venue !== 'kucoin') return;
    const R = kcFillRingFor(slot);
    if (R.busy) { try { await R.busy; } catch (e) {} if (!only) return; }
    const now = Date.now();
    if (!only && (now - (R.t || 0)) < KC_LIVE_TTL_MS) return;
    const creds = credsGet(slot);
    if (!creds || !creds.key || !creds.pass) return;
    R.t = now;
    R.route = routeNorm(route);   // the drain's multiplier warm dials the same route
    const mks = only ? [only === 'spot' ? 'spot' : 'futures'] : ['spot', 'futures'];
    const p = (async () => {
      for (const mk of mks) {
        const key = mk === 'spot' ? 'spTs' : 'fuTs';
        const F = mk === 'spot' ? R.sp : R.fu;
        const frm = R[key] > 0 ? Math.max(0, R[key] - KC_LIVE_OVERLAP_MS)
                               : now - KC_LIVE_COLD_MS;
        const w = await kcFillsWalk(creds, mk, frm, now + 1000, routeNorm(route),
                                    KC_LIVE_PAGES, KC_PAGE_GAP_MS);
        if (!w.ok) continue;                   // best-effort — next beat retries
        const fresh = [];
        kcFillPush(F, w.rows, fresh);
        kcPushFillRows(slot, mk, fresh);
        // The cursor is stamped with the SAME normalizer the stored row uses
        // (lbKcTsMs): a nanosecond futures stamp taken as ms parks the mark in
        // the year 56000 and the market never re-asks anything again.
        let hwm = R[key] || 0;
        for (const f of w.rows) { const t = lbKcTsMs(f); if (t > hwm) hwm = t; }
        R[key] = hwm > 0 ? hwm : Math.max(R[key] || 0, now - KC_LIVE_OVERLAP_MS);
      }
    })();
    R.busy = p;
    try { await p; } catch (e) { /* best-effort */ }
    if (R.busy === p) R.busy = null;
  }
  // Recent normalized live rows for the panel's fill chime / spot cost basis
  // (the chart triangles read the local STORE). Read-only view of the ring —
  // costs no REST call. Futures rows need the contract multiplier: a cold
  // entry drops the row from THIS share (never guesses 1 contract = 1 coin)
  // and the drain's retry sweep picks it up once kcMult landed.
  const KC_LIVE_SHARE_N = 200;
  function kcLiveFills(slot) {
    const R = kcFillRings[String(slot)];
    if (!R) return [];
    const out = [];
    for (const f of R.sp.rows) { const n = lbNormKucoinFill(f, 'spot', null); if (n) out.push(n); }
    for (const f of R.fu.rows) {
      const mc = kcMultCache[String((f && f.symbol) || '')];
      if (!(Number(mc && mc.v) > 0)) continue;
      const n = lbNormKucoinFill(f, 'futures', mc.v);
      if (n) out.push(n);
    }
    out.sort((a, b) => (a.ts || 0) - (b.ts || 0));
    return out.length > KC_LIVE_SHARE_N ? out.slice(out.length - KC_LIVE_SHARE_N) : out;
  }

  // KuCoin native account read (#1716): spot /api/v1/accounts (type=='trade'),
  // futures /api/v1/account-overview + /positions, paged active futures orders
  // (/orders?status=active) + untriggered stops (/stopOrders), spot active
  // orders (/api/v1/orders?status=active). RAW rows go back; the panel supplies
  // the ctVal map. Passphrase required (v2 signed header).
  async function execKucoinAcctRead(intent) {
    const creds = credsGet(intent.credSlot || 'kucoin');
    if (!creds) return { ok: false, message: 'No API key on this device — provision Native trading first' };
    if (!creds.pass) return { ok: false, message: 'KuCoin API passphrase missing — re-provision Native trading on this device' };
    const route = routeNorm(intent.route);
    // #2272: acct reads keep the two private push sockets warm (push-driven
    // display) — no-op while the loops already run. The read then RE-ATTACHES
    // push fills to the fresh snapshot panel-side (binance-shell-push rule).
    try { kcPushEnsure(intent.credSlot || 'kucoin', creds, route); } catch (e) { /* REST-only */ }
    // #2272 pump the LIVE fill lane on the account beat — the one beat that
    // always runs. Gated on intent.lblot (the panel sends it only while the
    // local blotter is ACTIVE for KuCoin), started in PARALLEL with the
    // account legs and awaited just before the reply: a slot that never uses
    // the local blotter pays exactly zero extra REST calls, and one that does
    // pays no extra wall-clock. lbKcLive keeps its own single-flight + TTL,
    // so N windows on one slot still cost ONE fetch per beat.
    const lbPump = intent.lblot
      ? lbKcLive('kucoin', intent.credSlot || 'kucoin', route).catch(() => {})
      : null;
    const spotAcc = await kcRequest(creds, 'GET', 'spot', '/api/v1/accounts', null, null, route);
    if (!spotAcc.ok) return spotAcc;
    const overview = await kcRequest(creds, 'GET', 'futures',
                                     '/api/v1/account-overview', [['currency', 'USDT']], null, route);
    if (!overview.ok) return overview;
    const pos = await kcRequest(creds, 'GET', 'futures', '/api/v1/positions', null, null, route);
    if (!pos.ok) return pos;
    // Paged list walk (KuCoin returns {data:{items,totalPage}}); cap at 10 pages.
    const pageWalk = async (market, path, extra) => {
      const rows = [];
      for (let page = 1; page <= 10; page++) {
        const params = [['currentPage', String(page)], ['pageSize', '200']].concat(extra || []);
        const r = await kcRequest(creds, 'GET', market, path, params, null, route);
        if (!r.ok) return r;
        const d = (r.data || {}).data || {};
        const items = Array.isArray(d.items) ? d.items : [];
        for (const o of items) rows.push(o);
        const totalPage = Number(d.totalPage) | 0;
        if (page >= totalPage || items.length < 200) break;
      }
      return { ok: true, rows: rows };
    };
    const fo = await pageWalk('futures', '/api/v1/orders', [['status', 'active']]);
    if (!fo.ok) return fo;
    const stops = await pageWalk('futures', '/api/v1/stopOrders', null);
    if (!stops.ok) return stops;
    const so = await pageWalk('spot', '/api/v1/orders', [['status', 'active']]);
    if (!so.ok) return so;
    // #2272 seed the per-symbol position subscriptions from the account's own
    // positions: KuCoin has no all-symbols position channel, so without this
    // the position row would only go push-driven after the first fill.
    const posRows = ((pos.data || {}).data) || [];
    try {
      kcPushPosWatch(intent.credSlot || 'kucoin',
                     (Array.isArray(posRows) ? posRows : [])
                       .map((p) => String((p || {}).symbol || '')).filter(Boolean));
    } catch (e) { /* push lane off */ }
    // #2272 additive: recent LOCAL fills for this credential slot (empty
    // unless the local blotter poll has warmed the ring for this slot). The
    // panel only reads it while the local blotter is ACTIVE for KuCoin —
    // capability alone must never suppress the server fills.
    if (lbPump) await lbPump;
    return { ok: true,
             spotAccounts: ((spotAcc.data || {}).data) || [],
             futOverview: (overview.data || {}).data || null,
             positions: posRows,
             futOrders: fo.rows, stopOrders: stops.rows, spotOrders: so.rows,
             lbFills: kcLiveFills(intent.credSlot || 'kucoin') };
  }
  // #2272 KuCoin futures leverage GET/SET (device-signed). KuCoin one-way
  // cross has NO dependable persistent set-leverage — `leverage` rides EACH
  // order — so the per-key + per-symbol memory is AUTHORITATIVE and the
  // cross-leverage endpoint is a best-effort sync so the KuCoin web UI
  // agrees. Engine KucoinAdapter.leverage_config / set_leverage twin.
  async function execKucoinLeverage(intent) {
    const what = String(intent.what || 'get');
    const symbol = String(intent.symbol || '');
    tdiag('trade', 'kucoin_lev', { s: intent.credSlot || 'kucoin', w: what, sym: symbol,
                                   lev: intent.leverage });
    if (!symbol) return { ok: false, message: 'symbol required' };
    const creds = credsGet(intent.credSlot || 'kucoin');
    if (!creds) return { ok: false, message: 'No API key on this device — provision Native trading first' };
    if (!creds.pass) return { ok: false, message: 'KuCoin API passphrase missing — re-provision Native trading on this device' };
    const route = routeNorm(intent.route);
    if (what === 'set') {
      const mag = Number(intent.leverage);
      if (!Number.isFinite(mag) || mag <= 0 || Math.floor(mag) !== mag) {
        return { ok: false, message: 'Leverage must be a positive whole number' };
      }
      const lev = String(Math.floor(mag));
      // The memory write is the source of truth and happens FIRST: the very
      // next order must carry the new leverage even if the account is a
      // classic one where the endpoint does not exist.
      kcLevMem[kcLevKey(creds, symbol)] = lev;
      const r = await kcRequest(creds, 'POST', 'futures', '/api/v2/changeCrossUserLeverage',
                                null, { symbol: symbol, leverage: lev }, route);
      if (!r.ok) tdiag('trade', 'kucoin_lev_sync', { sym: symbol, m: String(r.message || '').slice(0, 80) });
      return { ok: true, symbol: symbol, leverage: lev };
    }
    const mem = kcLevMem[kcLevKey(creds, symbol)];
    if (mem != null && String(mem)) return { ok: true, symbol: symbol, leverage: String(mem) };
    const r = await kcRequest(creds, 'GET', 'futures', '/api/v2/getCrossUserLeverage',
                              [['symbol', symbol]], null, route);
    if (r.ok) {
      const v = (((r.data || {}).data) || {}).leverage;
      if (v != null && Number(v) > 0) return { ok: true, symbol: symbol, leverage: String(v) };
    }
    // No memory and no readable venue setting: report the value orders will
    // actually carry rather than an empty chip.
    return { ok: true, symbol: symbol, leverage: KC_NATIVE_LEVERAGE };
  }

  // BitMEX native account read (#1716): /user/margin + /user/wallet (spot
  // balances) + PUBLIC /wallet/assets (scale map), /position, /order (both
  // markets — stops are plain orders). RAW rows + the scale map go back; the
  // panel supplies the per-symbol u2pm from its futures catalog.
  const BMX_SCALES_TTL_MS = 6 * 3600 * 1000;   // static public metadata (#1724)
  const _bmxScalesCache = { v: null, ts: 0 };
  async function execBitmexAcctRead(intent) {
    const creds = credsGet(intent.credSlot || 'bitmex');
    if (!creds) return { ok: false, message: 'No API key on this device — provision Native trading first' };
    const route = routeNorm(intent.route);
    const margin = await bmxRequest(creds, 'GET', '/user/margin',
                                    [['currency', 'all']], null, route);
    if (!margin.ok) return margin;
    const wallet = await bmxRequest(creds, 'GET', '/user/wallet',
                                    [['currency', 'all']], null, route);
    if (!wallet.ok) return wallet;
    const pos = await bmxRequest(creds, 'GET', '/position',
                                 [['filter', '{"isOpen":true}'], ['count', '500']], null, route);
    if (!pos.ok) return pos;
    const ord = await bmxRequest(creds, 'GET', '/order',
                                 [['filter', '{"open":true}'], ['count', '500'], ['reverse', 'true']], null, route);
    if (!ord.ok) return ord;
    // PUBLIC scale map (currency → scale) so spot amounts descale exactly like
    // the engine; a failed read leaves the panel's {XBt:8,USDt:6} fallback.
    // #1724: static public metadata — cached 6h so the poll train drops from
    // 5 to 4 requests (BitMEX budget is 120 req/min per key, the tightest of
    // all acct_read venues). Output shape unchanged (same map, same fallback).
    let scales = _bmxScalesCache.v;
    if (!scales || Date.now() - _bmxScalesCache.ts > BMX_SCALES_TTL_MS) {
      try {
        const rs = await httpJson(BITMEX_HOST, 'GET', BITMEX_API_PREFIX + '/wallet/assets',
                                  '', null, {}, route, 1024 * 1024);
        const ds = JSON.parse(rs.text);
        if (Array.isArray(ds)) {
          scales = {};
          for (const a of ds) {
            const c = String((a || {}).currency || '');
            const sc = (a || {}).scale;
            if (c && sc != null) scales[c] = Number(sc) | 0;
          }
          _bmxScalesCache.v = scales;
          _bmxScalesCache.ts = Date.now();
        }
      } catch (e) { /* fallback scales handled panel-side; keep any stale cache */ }
    }
    const arr = (r) => (Array.isArray(r.data) ? r.data : []);
    const marginRow = Array.isArray(margin.data)
      ? (margin.data.filter((m) => String((m || {}).currency || '') === 'USDt')[0] || margin.data[0] || null)
      : (margin.data || null);
    return { ok: true, margin: marginRow, wallet: arr(wallet),
             positions: arr(pos), orders: arr(ord), scales: scales };
  }

  // AsterDex native account read (#1716): Binance-family, EIP-712 signed.
  // Futures /fapi/v2/balance + /fapi/v2/positionRisk (rewritten to v3 by
  // ASTER_PATHS), spot /api/v3/account + /api/v3/openOrders (host sapi.*).
  // No algo API — stops ride the futures /fapi/v1/openOrders list.
  async function execAsterdexAcctRead(intent) {
    const creds = credsGet(intent.credSlot || 'asterdex');
    if (!creds) return { ok: false, message: 'No API key on this device — provision Native trading first' };
    const route = routeNorm(intent.route);
    const futBal = await asterRequest(creds, 'GET', 'futures', '/fapi/v2/balance', [], route);
    if (!futBal.ok) return futBal;
    const pos = await asterRequest(creds, 'GET', 'futures', '/fapi/v2/positionRisk', [], route);
    if (!pos.ok) return pos;
    const fo = await asterRequest(creds, 'GET', 'futures', '/fapi/v1/openOrders', [], route);
    if (!fo.ok) return fo;
    const spotAcc = await asterRequest(creds, 'GET', 'spot', '/api/v3/account', [], route);
    if (!spotAcc.ok) return spotAcc;
    const so = await asterRequest(creds, 'GET', 'spot', '/api/v3/openOrders', [], route);
    if (!so.ok) return so;
    return { ok: true,
             futBalance: Array.isArray(futBal.data) ? futBal.data : [],
             positions: Array.isArray(pos.data) ? pos.data : [],
             futOrders: Array.isArray(fo.data) ? fo.data : [],
             spotBalances: ((spotAcc.data || {}).balances) || [],
             spotOrders: Array.isArray(so.data) ? so.data : [] };
  }

  // Kraken native account read (#1716): dual-scope. Futures flex account
  // (/derivatives/api/v3/accounts, key2), openpositions, openorders (stops in
  // the same list). Spot BalanceEx + OpenOrders (spot key). RAW payloads go
  // back; the panel supplies the altname→symbol map from its spot catalog.
  // A failed futures scope surfaces its error (fail-closed, no partial spoof).
  async function execKrakenAcctRead(intent) {
    const creds = credsGet(intent.credSlot || 'kraken');
    if (!creds) return { ok: false, message: 'No API key on this device — provision Native trading first' };
    const route = routeNorm(intent.route);
    // #1804: private WS first — per SCOPE all-WS-or-all-REST (a partial WS
    // view never mixes with REST rows). REST fallback keeps the nonce
    // retry; the only steady-state REST nonce user is the rare token fetch.
    const sess = krWsEnsure(intent.credSlot || 'kraken', creds, route);
    if (sess) {
      // #1822: expire never-confirmed optimistic rows before serving reads
      // (fail-visible TTL — venue truth replaces confirmed ones in place).
      const nowP = Date.now();
      // #1860: expiry deletes ARE ledger writes — bump the scope seq
      {   // #1876: expiry deletions are diag-visible (kr_syn_expire)
        const nS = krSynPrune(sess.spot.orders, nowP);
        if (nS) { krLseq(sess.spot); krPushSc(sess.spot, 'order'); tdiag('acct', 'kr_syn_expire', { w: 'spot', n: nS }); }   // #1867
        const nF = krSynPrune(sess.fut.orders, nowP);
        if (nF) { krLseq(sess.fut); krPushSc(sess.fut, 'order'); tdiag('acct', 'kr_syn_expire', { w: 'fut', n: nF }); }   // #1867
      }
      // #1876: expired gone-order tombstones sweep on the same beat
      sess.spot.tombs = krTombSweep(sess.spot.tombs, nowP);
      sess.fut.tombs = krTombSweep(sess.fut.tombs, nowP);
    }
    const wsSpot = !!(sess && krWsLive(sess.spot) && sess.spot.totals != null);
    const wsFut = !!(sess && krWsLive(sess.fut));
    const out = { ok: true, wsSpot: wsSpot, wsFut: wsFut };
    if (sess) {
      // #1860: ledger seq stamps (diag/tests — panel ordering rides readSeq)
      out.lseqSpot = sess.spot.lseq | 0;
      out.lseqFut = sess.fut.lseq | 0;
      // #1860 failure honesty: log ledger source transitions (WS primary ↔
      // REST auditor) so diag shows exactly when the display went degraded.
      const pv = sess._wsSt || {};
      if (pv.spot !== wsSpot || pv.fut !== wsFut) {
        sess._wsSt = { spot: wsSpot, fut: wsFut };
        try {
          tdiag('acct', 'kr_ledger',
                { spot: wsSpot ? 1 : 0, fut: wsFut ? 1 : 0 });
        } catch (e) { /* diag-only */ }
      }
    }
    if (sess && (sess.spot.err || sess.fut.err)) {
      out.wsErr = sess.spot.err || sess.fut.err;
    }
    if (wsFut) {
      const F = sess.fut;
      out.flexAccount = krWsFlexRest(F.flex);
      const positions = [];
      for (const p of (F.positions || [])) {
        const row = krWsFutPosRest(p);
        if (row) positions.push(row);
      }
      out.positions = positions;
      const futOrders = [];
      for (const oid of Object.keys(F.orders)) futOrders.push(krWsFutOrderRest(F.orders[oid]));
      out.futOrders = futOrders;
    } else {
      const flex = await krRequest(creds, 'GET', 'futures',
                                   '/derivatives/api/v3/accounts', null, route);
      if (!flex.ok) return flex;
      const pos = await krRequest(creds, 'GET', 'futures',
                                  '/derivatives/api/v3/openpositions', null, route);
      if (!pos.ok) return pos;
      const fo = await krRequest(creds, 'GET', 'futures',
                                 '/derivatives/api/v3/openorders', null, route);
      if (!fo.ok) return fo;
      out.flexAccount = flex.data || null;
      out.positions = ((pos.data || {}).openPositions) || [];
      out.futOrders = ((fo.data || {}).openOrders) || [];
      // #1876: a stale REST page that still lists a just-removed order must
      // not resurrect its badge — tombstoned ids drop from the read result
      if (sess) {
        const tnowF = Date.now();
        out.futOrders = out.futOrders.filter(
          (o) => !krTombHit(sess.fut.tombs, String((o || {}).order_id || ''), tnowF,
                            KR_TOMB_SNAP_TTL_MS));   // #1878 snapshot-sourced → snap TTL
      }
      // #1860 ledger overlay: the REST page may predate just-ACKed orders —
      // fresh ledger rows absent from it are appended so badges never
      // vanish to a stale snapshot (stale ledger rows are NOT overlaid).
      if (sess) {
        const present = out.futOrders.map(
          (o) => String((o || {}).order_id || ''));
        const freshF = krLedgerFreshIds(sess.fut.orders, present, Date.now());
        for (const oid of freshF) {
          const row = krWsFutOrderRest(sess.fut.orders[oid]);
          if (row) out.futOrders.push(row);
        }
        if (freshF.length) out.synFut = freshF.length;
      }
    }
    if (wsSpot) {
      const S = sess.spot;
      out.spotBalances = krWsSpotBalanceEx(S.totals, krWsSpotHolds(S.orders));
      // altname map from the public catalog (cached; public GET, no nonce)
      let prods = null;
      try { prods = await krProducts(route); } catch (e) { prods = null; }
      out.spotOrders = krWsSpotOpenOrders(S.orders, (prods || {}).spot || {});
    } else {
      const bal = await krRequest(creds, 'POST', 'spot', '/0/private/BalanceEx', null, route,
                                  false, 0, false, !!intent.__hot);   // #2131 hot claim
      if (!bal.ok) return bal;
      const so = await krRequest(creds, 'POST', 'spot', '/0/private/OpenOrders', null, route,
                                 false, 0, false, !!intent.__hot);   // #2131 hot claim
      if (!so.ok) return so;
      // Flatten the spot OpenOrders map to [{txid, o}] preserving the ids.
      const spotOrders = [];
      const openMap = (((so.data || {}).result) || {}).open || {};
      for (const txid of Object.keys(openMap)) {
        // #1876: tombstoned (just-removed) ids never resurrect off a stale page
        if (sess && krTombHit(sess.spot.tombs, txid, Date.now(), KR_TOMB_SNAP_TTL_MS)) continue;   // #1878 snapshot-sourced → snap TTL
        spotOrders.push({ txid: txid, o: openMap[txid] });
      }
      // #1860 ledger overlay (same rule as futures above): fresh optimistic /
      // just-echoed spot rows missing from the REST page are appended in the
      // same [{txid, o}] shape via the WS→REST mapper.
      if (sess) {
        const freshS = krLedgerFreshIds(
          sess.spot.orders, spotOrders.map((r2) => r2.txid), Date.now());
        if (freshS.length) {
          let prods = null;
          try { prods = await krProducts(route); } catch (e) { prods = null; }
          const sub = {};
          for (const oid of freshS) sub[oid] = sess.spot.orders[oid];
          for (const row of krWsSpotOpenOrders(sub, (prods || {}).spot || {})) {
            spotOrders.push(row);
          }
          out.synSpot = freshS.length;
        }
      }
      out.spotBalances = bal.data || null;
      out.spotOrders = spotOrders;
    }
    return out;
  }

  // --- #1826 Kraken post-trade fast lane (runtime) --------------------------
  // Every successful kraken trade ack: (1) bust the acct_read memo for the
  // slot (next read reflects the optimistic echo, not a pre-ack snapshot);
  // (2) spot acks additionally schedule ONE bounded venue-truth REST confirm
  // (BalanceEx + OpenOrders) via the pure krConfirm* gate — coalesced across
  // ack bursts, min-gapped, at most one in flight — that refreshes S.totals
  // and drops confirmed-gone synthetics early. Fires independent of panel
  // polling (updates shell WS session state; the next read, whenever it
  // comes, is correct). Truth rule kept: REST responses only, never
  // fabricated numbers. Steady-state REST avoidance kept: the lane runs
  // ONLY on trade acks (~2 spot-point calls per burst — negligible).
  const krConfirmLanes = {};   // slot → { st, creds, route }
  function krTradeAckKick(slot, creds, route, market) {
    slot = String(slot || 'kraken');
    try { execAcctRead.bust('kraken', slot); } catch (e) { /* diag-only */ }
    if (market !== 'spot') return;
    let L = krConfirmLanes[slot];
    if (!L) {
      L = krConfirmLanes[slot] =
        { st: { timerAt: null, running: false, again: false, lastEnd: 0 } };
    }
    L.creds = creds; L.route = route;   // freshest creds/route win
    krConfirmSchedule(slot, L);
  }
  function krConfirmSchedule(slot, L) {
    const wait = krConfirmKick(L.st, Date.now());
    if (wait == null) return;
    const t = setTimeout(() => { krConfirmRun(slot, L); }, wait);
    if (t && typeof t.unref === 'function') t.unref();
  }
  async function krConfirmRun(slot, L) {
    if (!krConfirmFire(L.st)) return;
    let goneN = 0;   // #1860 auditor disagreement count (rows venue said gone)
    let divA = null; // #1864 local-vs-audit totals divergence (asset names)
    try {
      const sess = krWsSessGet(slot);
      // #1870 stale-snapshot guard: stamp the pre-fetch ledger seq — a
      // snapshot fetched while the WS ledger moved is provably stale and is
      // DISCARDED (diag kr_audit_stale), never applied; a budget-deferred /
      // failed read never mutates the ledger at all (krAuditGate 'nodata').
      const balSeq0 = sess ? (sess.spot.lseq | 0) : 0;
      const bal = await krRequest(L.creds, 'POST', 'spot',
                                  '/0/private/BalanceEx', null, L.route);
      const balGate = krAuditGate(balSeq0, sess ? (sess.spot.lseq | 0) : 0,
                                  !!(bal.ok && bal.data));
      if (sess && bal.ok && balGate === 'stale') {
        tdiag('acct', 'kr_audit_stale', { k: slot, w: 'bal', seq0: balSeq0,
                                          seq: sess.spot.lseq | 0 });
      }
      if (bal.ok && sess && balGate === 'apply') {
        // #1864: BalanceEx is a background AUDITOR now, not the display path
        // — the local fill math (krFillTotalsApply) already moved the posrow.
        // Fill-touched assets inside the grace keep the LOCAL value (the REST
        // page may predate the fill); everything else takes venue truth, and
        // any REAL divergence on a settled asset is diag-logged before the
        // override (kr_audit_div) so a broken local ledger is visible.
        const aud = krTotalsAudit(sess.spot.totals || {},
                                  krBalanceExTotals(bal.data),
                                  sess.spot.fillTouch || null, Date.now(),
                                  null, null, sess.spot.fillDirs || null);
        sess.spot.totals = aud.totals;
        if (aud.div.length) {
          divA = aud.div.slice(0, 6);
          tdiag('acct', 'kr_audit_div', { k: slot, n: aud.div.length,
                                          a: divA.join(',').slice(0, 80) });
        }
        // #1884: audit value moved a recently-filled asset AGAINST the
        // fill's direction → provably stale page, LOCAL value kept (the
        // regression 1194→796→1194 becomes a diag line, never a display dip)
        if (aud.clamp && aud.clamp.length) {
          tdiag('acct', 'kr_audit_clamp', { k: slot, n: aud.clamp.length,
            a: aud.clamp.slice(0, 6).join(',').slice(0, 80) });
          // #1890: a clamp is a TIE (local vs venue) — schedule ONE paced
          // follow-up confirm so venue truth wins within seconds when the
          // local value was wrong (krTotalsAudit yields on the second
          // disagreement); previously the next confirm waited on the next
          // trade ACK, which never came while sell-all kept getting rejected.
          krConfirmSchedule(slot, L);
        }
        krLseq(sess.spot); krPushSc(sess.spot, 'bal');   // #1860/#1867 auditor correction
      }
      // #1832 trim: OpenOrders exists to reconcile confirmed-gone rows — an
      // EMPTY local map has nothing to reconcile, skip the point entirely.
      let so = { ok: true, skipped: true };
      if (!sess || Object.keys(sess.spot.orders || {}).length) {
        const soSeq0 = sess ? (sess.spot.lseq | 0) : 0;   // #1870 pre-fetch stamp
        const soT0 = Date.now();   // #1874 snapshot fetch-start stamp
        so = await krRequest(L.creds, 'POST', 'spot',
                             '/0/private/OpenOrders', null, L.route);
        if (so.ok && sess) {
          // #1870: the open map must EXIST in the body (a body-level error /
          // deferred read under HTTP 200 must never read as "no open
          // orders" — that wiped 5 live resting badges); and the ledger seq
          // must not have moved during the fetch (a fill/cancel landed → the
          // page is provably stale → discard, the next confirm re-audits).
          const openMap = (((so.data || {}).result) || {}).open;
          const soGate = krAuditGate(soSeq0, sess.spot.lseq | 0,
                                     !!(openMap && typeof openMap === 'object'));
          if (soGate === 'stale') {
            tdiag('acct', 'kr_audit_stale', { k: slot, w: 'ord', seq0: soSeq0,
                                              seq: sess.spot.lseq | 0 });
          } else if (soGate === 'apply') {
            const ids = Object.keys(openMap);
            // #1874 omission grace: snapshot omission may only remove rows
            // older than the birth grace, missing from TWO consecutive
            // post-birth snapshots; withheld omissions diag as kr_audit_omit
            const rec = krOrdersReconcile(sess.spot.orders, ids, Date.now(), soT0);
            // #1876: a page fetched after a removal that omits the id
            // confirms it gone — its tombstone has done its job. #1878: an
            // omitting (proven-stale) page confirms nothing — tombstones
            // survive so its adds stay blocked at the snap TTL.
            if (!rec.omit.length) sess.spot.tombs = krTombConfirm(sess.spot.tombs, ids, soT0);
            else tdiag('acct', 'kr_snap_stale', { k: slot, w: 'ord', n: rec.omit.length });
            if (rec.omit.length) {
              tdiag('acct', 'kr_audit_omit', { k: slot, w: 'ord',
                n: rec.omit.length, ids: rec.omit.slice(0, 6).join(',').slice(0, 80) });
            }
            if (rec.gone.length) {
              krLseq(sess.spot);
              for (const g of rec.gone) krPushSc(sess.spot, 'ordgone', g);   // #1867/#1874
              goneN = rec.gone.length;
            }
          }
        }
      }
      // #1828 fast venue-truth fills: one recent-window TradesHistory page
      // rides the same confirm (nonce-serialized signer, coalesced burst).
      // Rows convert to the SAME raw WS shapes as the #1820 seed, so the
      // exec-id dedupe (WS-v2 exec_id IS the TradesHistory txid) collapses
      // the REST copy with the later WS echo — the panel's fills lane sees
      // the fill ~1s after ack and the id-keyed chime rings ONCE, never
      // twice. Cache pushes are dedupe-only; the engine stays the archive's
      // sole writer via the panel's /native_fills POST.
      try {
        // #1832 trim: TradesHistory is the fast lane's priciest call (2 pts)
        // and only accelerates the fill chime — under ledger pressure skip
        // it outright (the WS echo still lands, just later; logged, not an
        // error). Priority (cancel) headroom is what the floor protects.
        const krP = krPairFor(L.creds, 'spot');
        const thOk = krP &&
          krLedgerPts(krLedgerFor(krP.key), Date.now()) >= KR_LEDGER_FLOOR + 3;
        if (!thOk) {
          tdiag('trade', 'kr_budget', { k: 'kraken',
            p: '/0/private/TradesHistory', act: 'skip_confirm' });
        }
        if (thOk && sess && sess.spot.fills) {
          let codeMap = {};
          try { codeMap = ((await krProducts(L.route)) || {}).spotCode || {}; } catch (e2) {}
          const th = await krRequest(L.creds, 'POST', 'spot',
            '/0/private/TradesHistory',
            [['start', String((Date.now() - KR_CONFIRM_TRADES_WINDOW_MS) / 1000)],
             // #1829: default consolidate_taker=true merges a taker order's
             // executions into ONE synthetic trade (own txid, avg px) that
             // sits beside the per-execution WS rows and double-counts qty.
             ['consolidate_taker', 'false']],
            L.route);
          if (th.ok) {
            const trades = ((((th.data || {}).result) || {}).trades) || {};
            for (const tid of Object.keys(trades)) {
              const e2 = krRestSpotWsRow(tid, trades[tid], codeMap);
              const r2 = e2 && krWsSpotFillRow(e2);
              if (r2) krFillsCachePush(sess.spot.fills, r2);
            }
          }
        }
      } catch (e) { /* best-effort: the WS echo remains the fallback */ }
      // the confirm changed session state — bust again so a read memoized
      // during the confirm can't serve the pre-confirm view for ~1.2s
      try { execAcctRead.bust('kraken', slot); } catch (e) { /* diag-only */ }
      // #1832 diag honesty: carry the first Kraken error string + skip flag —
      // body-level errors under HTTP 200 are otherwise invisible in the log.
      const kcd = { ok: !!(bal.ok && so.ok) };
      if (goneN) kcd.gone = goneN;   // #1860 auditor corrected the ledger
      if (divA) kcd.div = divA.length;   // #1864 totals divergence count
      if (bal.skipped || so.skipped) kcd.skipped = true;
      if (!kcd.ok) {
        kcd.err = String((!bal.ok && bal.message) || (!so.ok && so.message)
                         || '').slice(0, 120);
      }
      tdiag('acct', 'kr_confirm', kcd);
    } catch (e) { /* best-effort: the next steady-state read is the truth */ }
    if (krConfirmDone(L.st, Date.now())) krConfirmSchedule(slot, L);
  }

  // Kraken native fills read (#1814): the private WS sessions above INGEST
  // executions (spot WS-v2 `executions` trade events incl. the snap_trades
  // seed snapshot; futures ws/v1 `fills` feed incl. its last-100 snapshot)
  // into bounded per-scope caches. This op serves the cached RAW venue rows
  // for [startMs, endMs]; the panel POSTs them to the engine's /native_fills
  // where kraken-shape normalizers parse them (engine stays the archive's
  // ONLY writer — phemex precedent). Fail-visible per scope: a key pair
  // whose WS is not live fails the WHOLE read so the panel never advances
  // its coverage cursor over a blind spot (no REST fallback — steady-state
  // REST nonce use is exactly what #1804 removed).
  async function execKrakenFillsRead(intent) {
    const creds = credsGet(intent.credSlot || 'kraken');
    if (!creds) return { ok: false, message: 'No API key on this device — provision Native trading first' };
    const route = routeNorm(intent.route);
    const sess = krWsEnsure(intent.credSlot || 'kraken', creds, route);
    const now = Date.now();
    let end = Math.floor(Number(intent.endMs) || 0);
    if (!(end > 0) || end > now + 60000) end = now;
    let start = Math.floor(Number(intent.startMs) || 0);
    if (!(start > 0) || start >= end) start = end - 24 * 3600 * 1000;
    if (end - start > 26 * 3600 * 1000) start = end - 26 * 3600 * 1000;
    // #1905 clock-skew allowance: cached fill `ts` ride the VENUE clock while
    // the caller's endMs is the panel's PC clock — a PC clock behind the
    // venue made just-executed fills fall out of [start, end] and a whole
    // burst read as 0 rows until local time caught up (observed 65s hole).
    // Serving slightly-"future" rows is safe: panel merge and engine ingest
    // both dedupe by exec id.
    const hiEnd = end + KR_FILLS_TS_SKEW_MS;
    const out = { ok: true, wsSpot: false, wsFut: false, spot: [], futures: [] };
    if (krPairFor(creds, 'spot')) {
      if (!krFillsScopeReady(sess && krWsLive(sess.spot), sess && sess.spot.fills)) {
        return { ok: false, message: (sess && (sess.spot.err || sess.fut.err))
                                     || 'Kraken spot fills not seeded yet' };
      }
      out.wsSpot = true;
      out.spot = krFillsWindow(sess.spot.fills, start, hiEnd);
    }
    if (krPairFor(creds, 'futures')) {
      if (!krFillsScopeReady(sess && krWsLive(sess.fut), sess && sess.fut.fills)) {
        return { ok: false, message: (sess && (sess.fut.err || sess.spot.err))
                                     || 'Kraken futures fills not seeded yet' };
      }
      out.wsFut = true;
      out.futures = krFillsWindow(sess.fut.fills, start, hiEnd);
    }
    return out;
  }

  // #1820 one-shot REST own-trades SEED: on the post-trade kick (and once per
  // panel session) the panel asks for a REST copy of recent fills so first
  // paint and the archive never wait on the spot WS executions delivery
  // (observed ~5s late over proxied routes) or on the bounded reconnect
  // snapshots (last-50 spot / last-100 futures — an app restart loses fills
  // beyond them if they were never ingested). Rows convert to the SAME raw WS
  // shapes (krRestSpotWsRow / krRestFutWsRow) and dedupe by exec id — never a
  // second record of a fill the WS already cached. NOT a steady-state REST
  // poller (#1804 rule): strictly rate-limited per session, panel-triggered.
  // PAGED: default responses cover only the last ~50/100 rows (same bound as
  // the WS snapshots), so the seed walks the FULL panel POST window (24h)
  // with the engine walkers' cursors — spot start+ofs, futures lastFillTime —
  // bounded by KR_FILLS_SEED_MAX_PAGES and paced between calls.
  const KR_FILLS_SEED_MIN_MS = 15000;
  const KR_FILLS_SEED_WINDOW_MS = 24 * 3600 * 1000;  // = panel fresh-session POST window
  const KR_FILLS_SEED_MAX_PAGES = 15;                // = engine HIST_MAX_PAGES
  const KR_FILLS_SEED_PAGE_GAP_MS = 400;
  async function execKrakenFillsSeed(intent) {
    const creds = credsGet(intent.credSlot || 'kraken');
    if (!creds) return { ok: false, message: 'No API key on this device — provision Native trading first' };
    const route = routeNorm(intent.route);
    const sess = krWsEnsure(intent.credSlot || 'kraken', creds, route);
    if (!sess) return { ok: false, message: 'Kraken session unavailable' };
    const now = Date.now();
    if (sess.seedT && now - sess.seedT < KR_FILLS_SEED_MIN_MS) {
      return { ok: true, paced: true, spot: 0, futures: 0 };
    }
    sess.seedT = now;
    const startMs = now - KR_FILLS_SEED_WINDOW_MS;
    const out = { ok: true, spot: 0, futures: 0 };
    if (krPairFor(creds, 'spot')) {
      let codeMap = {};
      try { codeMap = ((await krProducts(route)) || {}).spotCode || {}; } catch (e) {}
      let ofs = 0;
      for (let page = 0; page < KR_FILLS_SEED_MAX_PAGES && ofs !== null; page++) {
        if (page) await new Promise((rs) => setTimeout(rs, KR_FILLS_SEED_PAGE_GAP_MS));
        const th = await krRequest(creds, 'POST', 'spot', '/0/private/TradesHistory',
          [['start', String(startMs / 1000)], ['end', String(now / 1000)],
           // #1829: per-execution rows only — the consolidated synthetic
           // trade (own txid) would double-count beside its WS legs.
           ['ofs', String(ofs)], ['consolidate_taker', 'false']], route);
        if (!th.ok) return th;
        const res = ((th.data || {}).result) || {};
        const trades = res.trades || {};
        const tids = Object.keys(trades);
        for (const tid of tids) {
          const e = krRestSpotWsRow(tid, trades[tid], codeMap);
          const r = e && krWsSpotFillRow(e);
          if (r && krFillsCachePush(sess.spot.fills, r)) out.spot++;
        }
        ofs = krSeedSpotNext(res, ofs, tids.length);
      }
    }
    if (krPairFor(creds, 'futures')) {
      let cursor = null;
      for (let page = 0; page < KR_FILLS_SEED_MAX_PAGES; page++) {
        if (page) await new Promise((rs) => setTimeout(rs, KR_FILLS_SEED_PAGE_GAP_MS));
        const fh = await krRequest(creds, 'GET', 'futures', '/derivatives/api/v3/fills',
          cursor ? [['lastFillTime', cursor]] : null, route);
        if (!fh.ok) return fh;
        const fills = ((fh.data || {}).fills) || [];
        for (const f of fills) {
          const e = krRestFutWsRow(f);
          const r = e && krWsFutFillRow(e);
          if (r && krFillsCachePush(sess.fut.fills, r)) out.futures++;
        }
        cursor = krSeedFutNext(fills, startMs);
        if (!cursor) break;
      }
    }
    return out;
  }

  // #1966 Kraken futures leverage preferences (native device-signed). The
  // server shares the SAME futures key with this signer — Kraken futures
  // nonces are strictly increasing PER KEY, so the device's venue-synced
  // nonce stream ratchets the watermark above the server clock and every
  // server-signed leverage call 502s (nonceBelowThreshold TOO_SMALL).
  // GET/PUT /derivatives/api/v3/leveragepreferences via krRequest (krFutSign,
  // venue-synced nonce, user's proxy route). Old shells fall through to
  // 'unknown op' — the panel detects that and keeps the server path.
  async function execKrakenLeverage(intent) {
    // #1973 field-test diag: every native op logs ONE outcome line (what/
    // symbol/ok/value/ms, errors verbatim) to the admin diag file.
    const _dgT0 = Date.now();
    const _dgLine = (res) => {
      tdiag('lev', 'native_op', { k: String(intent.symbol || ''),
        what: intent.what === 'set' ? 'set' : 'get',
        sym: String(intent.symbol || '').toUpperCase(),
        ok: res && res.ok ? 1 : 0,
        lev: res && res.ok ? String(res.leverage || '') : undefined,
        err: res && !res.ok ? String(res.message || 'error') : undefined,
        ms: Date.now() - _dgT0 });
      return res;
    };
    const creds = credsGet(intent.credSlot || 'kraken');
    if (!creds) return _dgLine({ ok: false, message: 'No API key on this device — provision Native trading first' });
    const route = routeNorm(intent.route);
    const sym = String(intent.symbol || '').toUpperCase();
    if (!sym) return _dgLine({ ok: false, message: 'symbol required' });
    if (intent.what === 'set') {
      const lev = parseInt(intent.leverage, 10);
      if (!isFinite(lev) || lev < 1) return _dgLine({ ok: false, message: 'Leverage must be at least 1x' });
      const r = await krRequest(creds, 'PUT', 'futures',
        '/derivatives/api/v3/leveragepreferences',
        [['symbol', sym], ['maxLeverage', String(lev)]], route);
      if (!r.ok) return _dgLine(r);
      return _dgLine({ ok: true, symbol: sym, leverage: String(lev) });
    }
    const r = await krRequest(creds, 'GET', 'futures',
      '/derivatives/api/v3/leveragepreferences', null, route);
    if (!r.ok) return _dgLine(r);
    return _dgLine({ ok: true, symbol: sym,
             leverage: krLevPrefPick(r.data, sym) });
  }

  // #2000 Hyperliquid per-asset leverage GET/SET — read via activeAssetData
  // (leverage.type cross/isolated + value), set via the signed updateLeverage
  // /exchange action. Builder-dex symbols resolve THEIR dex asset id through
  // hlSpec. Honest failures — the panel surfaces them verbatim.
  async function execHlLeverage(intent) {
    const _dgT0 = Date.now();
    const _dgLine = (res) => {
      tdiag('lev', 'native_op', { k: String(intent.symbol || ''),
        what: intent.what === 'set' ? 'set' : 'get',
        sym: String(intent.symbol || ''),
        ok: res && res.ok ? 1 : 0,
        lev: res && res.ok ? String(res.leverage || '') : undefined,
        err: res && !res.ok ? String(res.message || 'error') : undefined,
        ms: Date.now() - _dgT0 });
      return res;
    };
    const creds = credsGet(intent.credSlot || 'hyperliquid');
    if (!creds) return _dgLine({ ok: false, message: 'No API key on this device — provision Native trading first' });
    const route = routeNorm(intent.route);
    const sym = String(intent.symbol || '');
    if (!sym) return _dgLine({ ok: false, message: 'symbol required' });
    const sr = await hlSpec('futures', sym, route);
    if (!sr.ok) return _dgLine(sr);
    // reads key the MASTER address (agent creds see an empty account);
    // a failed probe is a hard error — never silently read the wrong user.
    // `user` is a READ key ONLY — the updateLeverage SET below signs via
    // hlExchange(creds, …) whose identity comes from creds.secret alone
    // (hlSignAction takes no address; agent keys keep their own identity).
    let user;
    try { user = await hlMasterResolve(String(creds.key).trim(), route); }
    catch (e) { return _dgLine({ ok: false, message: (e && e.message) || 'userRole probe failed' }); }
    if (intent.what === 'set') {
      const lev = parseInt(intent.leverage, 10);
      if (!isFinite(lev) || lev < 1) return _dgLine({ ok: false, message: 'Leverage must be at least 1x' });
      // preserve the account's current cross/isolated mode unless the intent
      // names one — updateLeverage always states isCross explicitly.
      let isCross;
      if (intent.marginMode != null && intent.marginMode !== '') {
        isCross = String(intent.marginMode) !== 'isolated';
      } else {
        const ra = await hlInfo({ type: 'activeAssetData', user: user, coin: sr.spec.wire }, route);
        if (!ra.ok) return _dgLine(ra);
        isCross = String((((ra.data || {}).leverage) || {}).type || '') !== 'isolated';
      }
      const r = await hlExchange(creds, { type: 'updateLeverage',
        asset: parseInt(sr.spec.asset, 10), isCross: !!isCross, leverage: lev }, route);
      if (!r.ok) return _dgLine(r);
      return _dgLine({ ok: true, symbol: sym, leverage: String(lev),
                       marginMode: isCross ? 'cross' : 'isolated' });
    }
    const ra = await hlInfo({ type: 'activeAssetData', user: user, coin: sr.spec.wire }, route);
    if (!ra.ok) return _dgLine(ra);
    const lv = ((ra.data || {}).leverage) || {};
    const mx = Number(((ra.data || {}).maxLeverage != null ? ra.data.maxLeverage : NaN));
    return _dgLine({ ok: true, symbol: sym,
             leverage: lv.value != null ? String(lv.value) : null,
             marginMode: String(lv.type || '') === 'isolated' ? 'isolated' : 'cross',
             maxLeverage: isFinite(mx) ? mx : undefined });
  }

  // #2051 Bybit leverage GET/SET — read via /v5/position/list (rows carry
  // leverage even flat), set via /v5/position/set-leverage (category linear,
  // buy/sellLeverage same value). retCode 110043 "leverage not modified" IS
  // success (the chip already shows the requested value). Honest failures —
  // the panel surfaces them verbatim.
  async function execBybLeverage(intent) {
    const _dgT0 = Date.now();
    const _dgLine = (res) => {
      tdiag('lev', 'native_op', { k: String(intent.symbol || ''),
        what: intent.what === 'set' ? 'set' : 'get',
        sym: String(intent.symbol || '').toUpperCase(),
        ok: res && res.ok ? 1 : 0,
        lev: res && res.ok ? String(res.leverage || '') : undefined,
        err: res && !res.ok ? String(res.message || 'error') : undefined,
        ms: Date.now() - _dgT0 });
      return res;
    };
    const creds = credsGet(intent.credSlot || 'bybit');
    if (!creds) return _dgLine({ ok: false, message: 'No API key on this device — provision Native trading first' });
    const route = routeNorm(intent.route);
    const sym = String(intent.symbol || '').toUpperCase();
    if (!sym) return _dgLine({ ok: false, message: 'symbol required' });
    if (intent.what === 'set') {
      const lev = parseFloat(intent.leverage);
      if (!isFinite(lev) || lev < 1) return _dgLine({ ok: false, message: 'Leverage must be at least 1x' });
      const r = await bybRequest(creds, 'POST', '/v5/position/set-leverage', null,
        { category: 'linear', symbol: sym,
          buyLeverage: String(lev), sellLeverage: String(lev) }, route);
      if (!r.ok && Number(r.code) !== 110043) return _dgLine(r);
      return _dgLine({ ok: true, symbol: sym, leverage: String(lev) });
    }
    const r = await bybRequest(creds, 'GET', '/v5/position/list',
      [['category', 'linear'], ['symbol', sym]], null, route);
    if (!r.ok) return _dgLine(r);
    let lev = null;
    for (const p of (((r.data || {}).result) || {}).list || []) {
      const v = bnNum(p.leverage);
      if (v && Number(v) > 0) { lev = v; break; }
    }
    return _dgLine({ ok: true, symbol: sym, leverage: lev });
  }

  // #2153 Gate futures leverage GET/POST (device-signed; engine
  // leverage_config/set_leverage twins). Gate convention: leverage '0'
  // means CROSS mode — the magnitude rides cross_leverage_limit; the set
  // path always selects cross (leverage=0&cross_leverage_limit=N), server
  // POST parity. A never-touched contract reads as null (chip shows the
  // venue default). DUAL position mode is fail-visible: the one-way
  // endpoints error there and the message surfaces verbatim — never a
  // silent default (gate-unified-detection rule).
  async function execGateLeverage(intent) {
    const _dgT0 = Date.now();
    const _dgLine = (res) => {
      tdiag('lev', 'native_op', { k: String(intent.symbol || ''),
        what: intent.what === 'set' ? 'set' : 'get',
        sym: String(intent.symbol || '').toUpperCase(),
        ok: res && res.ok ? 1 : 0,
        lev: res && res.ok ? String(res.leverage || '') : undefined,
        err: res && !res.ok ? String(res.message || 'error') : undefined,
        ms: Date.now() - _dgT0 });
      return res;
    };
    const creds = credsGet(intent.credSlot || 'gate');
    if (!creds) return _dgLine({ ok: false, message: 'No API key on this device — provision Native trading first' });
    const route = routeNorm(intent.route);
    const sym = String(intent.symbol || '');
    if (!sym) return _dgLine({ ok: false, message: 'symbol required' });
    const levOf = (p) => {
      let v = bnNum((p || {}).leverage);
      if (v == null || v === '0') v = bnNum((p || {}).cross_leverage_limit) || null;
      return v != null && Number(v) > 0 ? v : null;
    };
    if (intent.what === 'set') {
      const lev = parseFloat(intent.leverage);
      if (!isFinite(lev) || lev < 1) return _dgLine({ ok: false, message: 'Leverage must be at least 1x' });
      if (Math.floor(lev) !== lev) return _dgLine({ ok: false, message: 'Leverage must be a whole number' });
      const r = await gateRequest(creds, 'POST',
        '/futures/usdt/positions/' + encodeURIComponent(sym) + '/leverage',
        [['leverage', '0'], ['cross_leverage_limit', String(lev)]], null, route);
      if (!r.ok) return _dgLine(r);
      const row = Array.isArray(r.data) ? r.data[0] : r.data;
      return _dgLine({ ok: true, symbol: sym, leverage: levOf(row) || String(lev) });
    }
    const r = await gateRequest(creds, 'GET',
      '/futures/usdt/positions/' + encodeURIComponent(sym), null, null, route);
    if (!r.ok) {
      // engine twin: a never-touched contract 404s POSITION_NOT_FOUND —
      // that is "no configured leverage", not an error.
      if (/not found|not_found|does not exist/i.test(String(r.message || ''))) {
        return _dgLine({ ok: true, symbol: sym, leverage: null });
      }
      return _dgLine(r);
    }
    return _dgLine({ ok: true, symbol: sym, leverage: levOf(r.data) });
  }

  // #2247 Bitget futures leverage GET/POST (device-signed; engine
  // leverage_config/set_leverage twins). One-way CROSS by terminal
  // convention: the read is /mix/account/account's crossedMarginLeverage
  // (older payloads spell it crossMarginLeverage) and the write posts a
  // bare {symbol, productType, marginCoin, leverage} — NO holdSide, which
  // is the hedge-mode-only field (sending it in one-way mode is the 43011
  // "holdSide error" class). A symbol whose leverage was never configured
  // reads null (the chip shows the venue default), never an error.
  async function execBitgetLeverage(intent) {
    const _dgT0 = Date.now();
    const _dgLine = (res) => {
      tdiag('lev', 'native_op', { k: String(intent.symbol || ''),
        what: intent.what === 'set' ? 'set' : 'get',
        sym: String(intent.symbol || '').toUpperCase(),
        ok: res && res.ok ? 1 : 0,
        lev: res && res.ok ? String(res.leverage || '') : undefined,
        err: res && !res.ok ? String(res.message || 'error') : undefined,
        ms: Date.now() - _dgT0 });
      return res;
    };
    const creds = credsGet(intent.credSlot || 'bitget');
    if (!creds) return _dgLine({ ok: false, message: 'No API key on this device — provision Native trading first' });
    if (!creds.pass) return _dgLine({ ok: false, message: 'Bitget API passphrase missing — re-provision Native trading on this device' });
    const route = routeNorm(intent.route);
    const sym = String(intent.symbol || '');
    if (!sym) return _dgLine({ ok: false, message: 'symbol required' });
    const levOf = (d) => {
      const v = bnNum((d || {}).crossedMarginLeverage) || bnNum((d || {}).crossMarginLeverage);
      return v != null && Number(v) > 0 ? v : null;
    };
    if (intent.what === 'set') {
      const lev = parseFloat(intent.leverage);
      if (!isFinite(lev) || lev < 1) return _dgLine({ ok: false, message: 'Leverage must be at least 1x' });
      if (Math.floor(lev) !== lev) return _dgLine({ ok: false, message: 'Leverage must be a whole number' });
      const r = await bitgetRequest(creds, 'POST', '/api/v2/mix/account/set-leverage', null,
        { symbol: sym, productType: BITGET_PRODUCT_TYPE, marginCoin: 'USDT',
          leverage: String(lev) }, route);
      if (!r.ok) return _dgLine(r);
      return _dgLine({ ok: true, symbol: sym, leverage: String(lev) });
    }
    const r = await bitgetRequest(creds, 'GET', '/api/v2/mix/account/account',
      [['symbol', sym], ['productType', BITGET_PRODUCT_TYPE], ['marginCoin', 'USDT']],
      null, route);
    if (!r.ok) return _dgLine(r);
    return _dgLine({ ok: true, symbol: sym, leverage: levOf((r.data || {}).data) });
  }

  // #1844 own-trade HISTORY BACKFILL (device-keyed re-import source): page
  // the venue's own-trades REST over a caller-supplied [frm, to] window and
  // return the RAW rows in the SAME shapes the live ingest posts (Kraken:
  // WS-shaped rows via krRestSpotWsRow/krRestFutWsRow — kr_ingest_rows'
  // input; Phemex: /api-data trade rows keyed by symbol — fut/spot_fill_norm
  // input). The ENGINE normalizes (single parser truth) so dedup keys are
  // byte-identical to live/seed copies — the #1820 dupe-class rule. Paced
  // (page gaps) and bounded (page caps, 92d window); read-only signed GETs
  // ride the same per-venue request guards as the seed (LOW priority — no
  // trading headroom touched). One in flight at a time.
  const HB_MAX_SPAN_MS = 92 * 86400 * 1000;
  const HB_PAGE_GAP_MS = 450;
  const HB_KR_MAX_PAGES = 40;          // ≥ 2000 spot rows / 4000 fut rows
  const HB_PH_MAX_CALLS = 60;          // 26h chunks × symbols bound
  let _hbBusy = false;
  function hbWindow(intent) {
    const now = Date.now();
    let to = Math.floor(Number(intent.to) || 0);
    if (!(to > 0) || to > now + 60000) to = now;
    let frm = Math.floor(Number(intent.frm) || 0);
    if (!(frm > 0) || frm >= to) return null;
    if (to - frm > HB_MAX_SPAN_MS) return null;
    return { frm: frm, to: to };
  }
  async function execHistoryBackfill(intent) {
    if (_hbBusy) return { ok: false, message: 'history backfill already in flight' };
    _hbBusy = true;
    try {
      if (intent.venue === 'kraken') return await hbKraken(intent);
      if (intent.venue === 'phemex') return await hbPhemex(intent);
      return { ok: false, message: 'history_backfill not supported for this venue — re-import runs with a server-stored key' };
    } finally { _hbBusy = false; }
  }
  async function hbKraken(intent) {
    const creds = credsGet(intent.credSlot || 'kraken');
    if (!creds) return { ok: false, message: 'No API key on this device — provision Native trading first' };
    const w = hbWindow(intent);
    if (!w) return { ok: false, message: 'Bad window (max 92 days)' };
    const route = routeNorm(intent.route);
    const market = String(intent.market || 'both');
    const out = { ok: true, spot: [], futures: [] };
    // #2168: hold the ledger reservation for the walk itself (covers the
    // direct desktop re-import call path; the lblot retry ladder holds its
    // own — counted, nesting is fine). Released in finally, always.
    const resv = krResvFor(intent.credSlot || 'kraken');
    resv.acquire();
    try {
    if (market !== 'futures' && krPairFor(creds, 'spot')) {
      let codeMap = {};
      try { codeMap = ((await krProducts(route)) || {}).spotCode || {}; } catch (e) {}
      let ofs = 0;
      for (let page = 0; page < HB_KR_MAX_PAGES && ofs !== null; page++) {
        if (page) await new Promise((rs) => setTimeout(rs, HB_PAGE_GAP_MS));
        // _hot=true: the walk's own claims ride the bounded hot-wait lane
        // (wait for refill instead of budget-skip) — with the reservation
        // pausing routine polls, attempt 1-2 should now win the claim.
        const th = await krRequest(creds, 'POST', 'spot', '/0/private/TradesHistory',
          [['start', String(w.frm / 1000)], ['end', String(w.to / 1000)],
           // #1829: per-execution rows only — never the consolidated synthetic.
           ['ofs', String(ofs)], ['consolidate_taker', 'false']], route,
          false, 0, false, true);
        if (!th.ok) return th;   // fail-visible: never a partial snapshot
        const res = ((th.data || {}).result) || {};
        const trades = res.trades || {};
        const tids = Object.keys(trades);
        for (const tid of tids) {
          const e = krRestSpotWsRow(tid, trades[tid], codeMap);
          if (e) out.spot.push(e);
        }
        ofs = krSeedSpotNext(res, ofs, tids.length);
      }
      // Page-cap exhaustion = INCOMPLETE snapshot — reject, never let a
      // truncated backfill become authoritative venue truth.
      if (ofs !== null) return { ok: false, message: 'Window too large — spot history exceeds the page cap; narrow the date range' };
    }
    if (market !== 'spot' && krPairFor(creds, 'futures')) {
      let cursor = new Date(w.to).toISOString();
      for (let page = 0; page < HB_KR_MAX_PAGES; page++) {
        if (page) await new Promise((rs) => setTimeout(rs, HB_PAGE_GAP_MS));
        const fh = await krRequest(creds, 'GET', 'futures', '/derivatives/api/v3/fills',
          [['lastFillTime', cursor]], route);
        if (!fh.ok) return fh;
        const fills = ((fh.data || {}).fills) || [];
        for (const f of fills) {
          const e = krRestFutWsRow(f);
          if (e && e.time >= w.frm && e.time <= w.to) out.futures.push(e);
        }
        cursor = krSeedFutNext(fills, w.frm);
        if (!cursor) break;
      }
      if (cursor) return { ok: false, message: 'Window too large — futures history exceeds the page cap; narrow the date range' };
    }
    return out;
    } finally { resv.release(); }
  }
  async function hbPhemex(intent) {
    const creds = credsGet(intent.credSlot || 'phemex');
    if (!creds) return { ok: false, message: 'No API key on this device — provision Native trading first' };
    const w = hbWindow(intent);
    if (!w) return { ok: false, message: 'Bad window (max 92 days)' };
    const route = routeNorm(intent.route);
    const symsOf = (v) => (Array.isArray(v) ? v : []).map(String)
      .filter((s) => s && s.length <= 32 && /^[A-Za-z0-9]+$/.test(s)).slice(0, 12);
    const futSyms = symsOf(intent.futSymbols);
    const spotSyms = symsOf(intent.spotSymbols);
    if (!futSyms.length && !spotSyms.length) {
      return { ok: false, message: 'Phemex history needs explicit symbols (venue API is per-symbol)' };
    }
    // /api-data trades: per-symbol, start/end-bounded, limit 200 — walk the
    // window in 26h chunks (same bound the live fills read uses).
    const CHUNK = 26 * 3600 * 1000;
    let calls = 0;
    const futures = {}, spot = {};
    const walk = async (path, sym, dst) => {
      dst[sym] = dst[sym] || [];
      for (let t0 = w.frm; t0 < w.to; t0 += CHUNK) {
        if (++calls > HB_PH_MAX_CALLS) {
          return { ok: false, message: 'Window too large for the symbol count — narrow the range' };
        }
        if (calls > 1) await new Promise((rs) => setTimeout(rs, HB_PAGE_GAP_MS));
        const t1 = Math.min(t0 + CHUNK, w.to);
        const r = await signedRequest(creds, {
          method: 'GET', path: path,
          query: 'symbol=' + encodeURIComponent(sym) + '&start=' + t0 + '&end=' + t1 + '&limit=200',
          body: null }, route);
        if (!r.ok) return r;
        const rows = (r.data && r.data.rows) || (Array.isArray(r.data) ? r.data : []);
        // A full page = possibly TRUNCATED chunk — reject rather than let an
        // incomplete snapshot become authoritative venue truth.
        if (rows.length >= 200) {
          return { ok: false, message: sym + ': too many trades in one chunk — narrow the date range' };
        }
        for (const row of rows) dst[sym].push(row);
      }
      return { ok: true };
    };
    for (const sym of futSyms) {
      const r = await walk('/api-data/g-futures/trades', sym, futures);
      if (!r.ok) return r;
    }
    for (const sym of spotSyms) {
      const r = await walk('/api-data/spots/trades', sym, spot);
      if (!r.ok) return r;
    }
    return { ok: true, futures: futures, spot: spot };
  }

  // Phemex PUBLIC catalog/kline fetch (#1713): unsigned bridge intent for the
  // panel's "Catalogs & candles: Native" axis (Phemex REST has no CORS, so
  // the fetch must run here in the main process; honors the user proxy via
  // the shared keep-alive agent cache inside httpJson). STRICT allowlist —
  // /public/products and the two public kline endpoints only, never an open
  // proxy. No creds involved.
  const PHEMEX_KLINE_TFS = [60, 300, 900, 1800, 3600];
  // Generic PUBLIC catalog/kline raw-GET bridge (#1716): the RELAY-ONLY /
  // CORS-closed venues (KuCoin, Gate, BitMEX, Kraken, MEXC, Arcus) whose
  // catalogs+klines the browser can only reach via the server relay. On the
  // desktop app the Electron MAIN process CAN dial their PUBLIC REST directly
  // (CORS is irrelevant here), so the panel sends the SAME venue-relative path
  // it would hand its relay endpoint and we execute the raw GET. The RAW BODY
  // TEXT goes back verbatim — the panel's own parser stays the single source
  // of truth, so output is byte-identical to the relay path. STRICT static
  // allowlist per venue+market: exact host + path PREFIXES covering ONLY the
  // catalog + candle/kline surface (mirrors main.py's relay allowlists). GET
  // only, no creds, no open proxy. The key is (hostMarket||market) so Arcus'
  // spot catalog — which rides the FUTURES host — resolves the arcus|futures
  // entry (the panel passes hostMarket='futures' for that one call, exactly
  // like _catVFetch's hostMarket quirk).
  // Browser-style headers for Cloudflare-fronted venue REST. Kraken spot
  // (api.kraken.com) sits entirely behind Cloudflare, which fingerprints
  // UA-less Node requests on cold/idle proxy tunnels and kills them at the
  // CONNECTION level (resets — the panel sees status-0 errNet every poll;
  // same bot-wall family as the Lighter 405s). A plain browser UA + Accept
  // keeps the raw GET on the SAME proxy route (no silent bypass) while
  // presenting as ordinary client traffic. Other venues stay header-less —
  // byte-identical behavior where nothing is broken.
  const CAT_BROWSER_HDRS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Accept': 'application/json',
  };
  const CAT_GET_ALLOW = {
    'kucoin|spot':    { host: 'api.kucoin.com',         base: '', prefixes: ['/api/v2/symbols', '/api/v1/market/candles'] },
    'kucoin|futures': { host: 'api-futures.kucoin.com', base: '', prefixes: ['/api/v1/contracts/active', '/api/v1/kline/query'] },
    'gate|spot':      { host: 'api.gateio.ws', base: '/api/v4', prefixes: ['/spot/currency_pairs', '/spot/candlesticks'] },
    'gate|futures':   { host: 'api.gateio.ws', base: '/api/v4', prefixes: ['/futures/usdt/contracts', '/futures/usdt/candlesticks'] },
    'bitmex|spot':    { host: 'www.bitmex.com', base: '', prefixes: ['/api/v1/instrument/active', '/api/v1/trade/bucketed'] },
    'bitmex|futures': { host: 'www.bitmex.com', base: '', prefixes: ['/api/v1/instrument/active', '/api/v1/trade/bucketed'] },
    // MEXC carries EXTRA public read prefixes beyond catalog+kline (trade
    // seeds + tickers): both hosts are CORS-closed in browsers, so the
    // remaining public REST legs ride this same raw-GET bridge on desktop
    // (panel gates them on the 'cat:mexc2' cap — see preload.js).
    'mexc|spot':      { host: 'api.mexc.com',      base: '', prefixes: ['/api/v3/exchangeInfo', '/api/v3/klines', '/api/v3/trades', '/api/v3/ticker/24hr', '/api/v3/ticker/price'] },
    'mexc|futures':   { host: 'contract.mexc.com', base: '', prefixes: ['/api/v1/contract/detail', '/api/v1/contract/kline/', '/api/v1/contract/deals/', '/api/v1/contract/ticker'] },
    'kraken|spot':    { host: 'api.kraken.com',     base: '', prefixes: ['/0/public/AssetPairs', '/0/public/OHLC', '/0/public/Trades'], hdrs: CAT_BROWSER_HDRS },   // Trades: #1982 cluster deep-history forward pager
    'kraken|futures': { host: 'futures.kraken.com', base: '', prefixes: ['/derivatives/api/v3/instruments', '/api/charts/v1/trade/'], hdrs: CAT_BROWSER_HDRS },
    // Arcus futures host also carries the SPOT catalog overview (hostMarket
    // quirk) → its prefix list includes /v1/api-meta/spot/overview.
    'arcus|futures':  { host: 'api.arcus.xyz',            base: '', prefixes: ['/v1/markets', '/v1/candles', '/v1/api-meta/spot/overview'] },
    'arcus|spot':     { host: 'indexer.spot.arcus.xyz',   base: '', prefixes: ['/token-candles/'] },
  };
  // 8MB cap: full venue catalogs (KuCoin symbols, MEXC exchangeInfo, etc.)
  // routinely exceed httpJson's 256KB default — a truncated body would fail
  // the panel parser (see .agents/memory/shell-httpjson-response-cap.md).
  // #1945: 16MB (spot exchangeInfo with permission sets measured 8.4MB —
  // just over the old 8MB cap; the truncated JSON failed the panel parser
  // as a silent "unknown symbol" mystery). Truncation is now ALSO an
  // explicit {ok:false} below — the cap can never silently clip again.
  const CAT_GET_MAXBYTES = 16 * 1024 * 1024;
  // Generic PUBLIC catalog/kline bridge (#1715): CORS-open venues' catalog +
  // chart-history fetches move out of the renderer into this main-process
  // intent so EACH request carries its own Proxy/Direct agent (agentFor's
  // shared keep-alive cache — never per-request agents; flushed on proxy
  // change). STRICT allowlist: https only, no embedded creds, the host must
  // belong to the venue's static VENUE_ROUTE_HOSTS entries (the renderer can
  // never widen egress), GET only — plus Hyperliquid's POST /info (its
  // public catalog API is POST-shaped, body capped). No keys involved.
  function catHttpHostsFor(venue) {
    const out = [];
    for (const k of Object.keys(VENUE_ROUTE_HOSTS)) {
      if (k.slice(0, k.indexOf('|')) !== venue) continue;
      for (const h of VENUE_ROUTE_HOSTS[k]) if (out.indexOf(h) < 0) out.push(h);
    }
    return out;
  }
  // #2230 ONE shared instance for the whole public-data bridge: every window's
  // catalog/ticker/kline GET rides it, so the app fetches a given payload once
  // instead of once per open window. Signed/account reads keep their own
  // acctReadGuard — this guard only ever sees unsigned public GETs.
  const catShare = catShareGuard(Date.now, (ev, info) => tdiag('cat', ev, info));
  async function execCatHttp(intent) {
    const venue = String(intent.venue || '');
    const hosts = catHttpHostsFor(venue);
    if (!hosts.length) return { ok: false, message: 'native catalog fetch not supported for this venue' };
    let u;
    try { u = new URL(String(intent.url || '')); } catch (e) { return { ok: false, message: 'bad url' }; }
    if (u.protocol !== 'https:' || u.username || u.password) return { ok: false, message: 'bad url' };
    if (hosts.indexOf(u.hostname) < 0) return { ok: false, message: 'host not allowed for this venue' };
    let method = 'GET', body = null;
    if (intent.method === 'POST') {
      if (venue !== 'hyperliquid' || u.pathname !== '/info') return { ok: false, message: 'POST not allowed' };
      body = (typeof intent.body === 'string') ? intent.body : '';
      if (body.length > 4096) return { ok: false, message: 'body too large' };
      method = 'POST';
    }
    const route = routeNorm(intent.route);
    // #2008: the bridge's one allowed POST is an HL /info read — it must ride
    // the same shared budget as shell hlInfo or panel callers (leverage GET,
    // pub-reads) escape the pacing entirely.
    let _hlTyp = '';
    if (method === 'POST') {
      try { _hlTyp = String((JSON.parse(body) || {}).type || ''); } catch (e) {}
      await _hlBudgetGate(_hlTyp);
    }
    const run = async () => {
      try {
        // Catalogs can be huge (full product lists) — same cap as the generic
        // cat_fetch GET branch; httpJson's default 256 KB would truncate.
        const r = await httpJson(u.hostname, method, u.pathname, u.search.replace(/^\?/, ''),
                                 body, {}, route, CAT_GET_MAXBYTES);
        // #1945: a body clipped at the cap is an EXPLICIT failure — the panel
        // surfaces it in the picker error row instead of a JSON.parse mystery.
        if (method === 'POST') {
          if ((r.status | 0) === 429) hlBudget429(_hlBudget, Date.now(), 0);
          else if ((r.status | 0) === 200) hlBudgetOk(_hlBudget);
        }
        if (r && r.tr) return { ok: false, message: 'catalog response truncated at size cap' };
        return { ok: true, status: r.status | 0, body: r.text || '' };
      } catch (e) {
        const em = (e && e.message) || 'error';
        if (em === 'proxy-unavailable') return { ok: false, message: 'Proxy is enabled but unavailable' };
        return { ok: false, message: 'catalog fetch failed: ' + em };
      }
    };
    // #2230: GETs are shared app-wide (single-flight + start-stamped
    // freshness). The one POST this bridge allows (HL /info) keeps its
    // byte-identical path — it already rides the shared HL weight budget.
    if (method !== 'GET') return await run();
    return await catShare('h|' + venue + '|' + route + '|' + u.hostname + '|' +
                          u.pathname + '|' + u.search, run, { v: venue, p: u.pathname });
  }
  async function execCatFetch(intent) {
    const route = routeNorm(intent.route);
    // Generic raw-GET branch (#1716) — must precede the phemex-only gate so
    // the six relay-only venues route here; phemex keeps its typed branches.
    if (intent.what === 'get') {
      const venue = String(intent.venue || '');
      const market = intent.market === 'spot' ? 'spot' : 'futures';
      const hostMarket = intent.hostMarket === 'futures' ? 'futures'
                       : intent.hostMarket === 'spot' ? 'spot' : market;
      const ent = CAT_GET_ALLOW[venue + '|' + hostMarket];
      if (!ent) return { ok: false, message: 'native catalog fetch not allowed for this venue/market' };
      const raw = String(intent.path || '');
      if (!raw || raw.length > 4096 || raw.indexOf('//') === 0)
        return { ok: false, message: 'bad path' };
      const qi = raw.indexOf('?');
      const pathOnly = qi >= 0 ? raw.slice(0, qi) : raw;
      const query = qi >= 0 ? raw.slice(qi + 1) : '';
      if (pathOnly.indexOf('/') !== 0 || pathOnly.indexOf('..') >= 0)
        return { ok: false, message: 'bad path' };
      if (!ent.prefixes.some((p) => pathOnly === p || pathOnly.indexOf(p) === 0))
        return { ok: false, message: 'path not in catalog allowlist' };
      const run = async () => {
        let r;
        try {
          r = await httpJson(ent.host, 'GET', ent.base + pathOnly, query,
                             null, ent.hdrs || {}, route, CAT_GET_MAXBYTES);
        } catch (e) {
          // Surface the REAL transport error (code + message) — "network error"
          // debugging must never require guessing timeout vs ECONNRESET vs
          // proxy CONNECT failure (the panel crumb log carries this verbatim).
          const code = (e && e.code) ? String(e.code) + ' ' : '';
          return { ok: false, message: 'catalog fetch failed: ' + code + ((e && e.message) || 'error') };
        }
        // #1945: truncated-at-cap bodies fail explicitly (never a parse mystery).
        if (r && r.tr) return { ok: false, message: 'catalog response truncated at size cap' };
        // Non-2xx still returns ok:true with the status so the panel can treat
        // the reply like a fetch Response (new Response(text, {status})). The
        // RAW body text goes back untouched — the panel parser owns the shape.
        return { ok: true, status: (r && r.status) || 0, text: (r && r.text) || '' };
      };
      // #2230: shared app-wide — five windows opening the same board fetch the
      // catalog ONCE (single-flight), and a sixth arriving seconds later reuses
      // it (freshness stamped at request start).
      return await catShare('g|' + venue + '|' + hostMarket + '|' + route + '|' +
                            ent.host + '|' + ent.base + pathOnly + '|' + query,
                            run, { v: venue, p: pathOnly });
    }
    if (intent.venue !== 'phemex') return { ok: false, message: 'native catalog fetch not supported for this venue' };
    if (intent.what === 'products') {
      try {
        const pr = await phemexProducts(route);
        return { ok: true, data: pr.raw || {} };
      } catch (e) {
        return { ok: false, message: 'catalog fetch failed: ' + ((e && e.message) || 'error') };
      }
    }
    if (intent.what === 'kline') {
      const market = intent.market === 'spot' ? 'spot' : 'futures';
      const symbol = String(intent.symbol || '');
      const tf = Number(intent.tf) | 0;
      if (!symbol || symbol.length > 32 || !/^[A-Za-z0-9]+$/.test(symbol))
        return { ok: false, message: 'bad symbol' };
      if (PHEMEX_KLINE_TFS.indexOf(tf) < 0) return { ok: false, message: 'bad tf' };
      const now = Math.floor(Date.now() / 1000);
      let to = Number(intent.to) | 0;
      if (!(to > 0) || to > now + 60) to = now;
      let n = Number(intent.n) | 0;
      if (!(n >= 10)) n = 500;
      if (n > 1000) n = 1000;
      const frm = Math.max(0, to - n * tf);
      const path = market === 'futures' ? '/exchange/public/md/v2/kline/list'
                                        : '/exchange/public/md/kline';
      let pscale = 0, vscale = 0;
      if (market === 'spot') {
        try {
          const pr = await phemexProducts(route);
          const sp = pr.spot[symbol];
          if (!sp) return { ok: false, message: 'unknown symbol' };
          pscale = sp.pscale | 0;
          vscale = sp.value_scale | 0;
        } catch (e) {
          return { ok: false, message: 'catalog fetch failed: ' + ((e && e.message) || 'error') };
        }
      }
      let r;
      try {
        r = await httpJson(PHEMEX_HOST, 'GET', path,
                           'symbol=' + encodeURIComponent(symbol) + '&resolution=' + tf +
                           '&from=' + frm + '&to=' + to,
                           null, {}, route, 4 * 1024 * 1024);
      } catch (e) {
        return { ok: false, message: 'kline fetch failed: ' + ((e && e.message) || 'error') };
      }
      if (!r || r.status !== 200) return { ok: false, message: 'kline fetch failed (HTTP ' + ((r && r.status) || 0) + ')' };
      let data;
      try { data = JSON.parse(r.text); } catch (e) { return { ok: false, message: 'kline parse failed' }; }
      if (!data || data.code !== 0) return { ok: false, message: 'kline upstream code ' + ((data && data.code) != null ? data.code : '?') };
      return { ok: true, data: data, pscale: pscale, vscale: vscale };
    }
    return { ok: false, message: 'unknown cat_fetch kind' };
  }

  // ── #1969 device-local blotter (runtime) ─────────────────────────────────
  // Persistent per-scope (venue#aN cred slot) fills archive on the device:
  // the panel renders "Your trades" from HERE for native-armed venues and
  // the server participates in NOTHING during trading. Writes are exactly-
  // once (lbScopeMerge seen-key dedupe + tombstones), size-bounded with the
  // POSITION-AWARE prune (lbPruneRows — never a bare ts cutoff), persisted
  // as JSON in userData (same convention as trade_creds.json; fill rows are
  // not secrets). All desktop windows read the same truth through the one
  // main-process store.
  const LB_ROWS_CAP = 20000;               // per scope, prune is position-aware
  const LB_SAVE_DEBOUNCE_MS = 1500;
  const _lbQuarSig = {};                   // #2098 per-slot quar-tap dedupe
  // #2098 silent-drop diag: every cap-triggered prune that actually removes
  // rows leaves a tap — trade rows must never vanish without a log line.
  function lbPruneTap(slot, venue, sc) {
    const before = sc.rows.length;
    sc.rows = lbPruneRows(sc.rows, LB_ROWS_CAP);
    sc.seen = null;
    const n = before - sc.rows.length;
    if (n) {
      // #2234: rows vanished — the replay cache's per-group signatures cannot
      // see that on their own, and the drain cursors must re-scan from the
      // ring head (a pruned row may still sit in a live ring). A prune also
      // has to reach the snapshot, or a journal replay would resurrect the
      // pruned rows on the next launch.
      lbStoreMut(slot, sc);
      lbSnapSoon(0);
      tdiag('lblot', 'prune', { k: slot, v: venue, n: n,
        total: sc.rows.length, reason: 'rows-cap' });
    }
  }
  // Every NON-APPEND mutation of a scope (delete, prune, tombstone clear,
  // re-import) goes through here (#2234): it busts the per-group replay cache
  // wholesale — a group signature is (rows, first key, last key) and cannot
  // detect "one row removed from the middle and one inserted" — and drops the
  // incremental drain cursors so the next drain re-reads its rings in full.
  function lbStoreMut(slot, sc) {
    if (sc) { sc._ep = (sc._ep | 0) + 1; sc._rep = null; }
    _lbDrainAt[slot] = null;
    _lbDrainCur[slot] = null;
  }
  // --- persistence: append-only journal + rare atomic snapshot (#2234) -----
  // WAS: every merged fill scheduled a save that stringified the WHOLE store
  // (3.4 MB) and wrote it with a SYNCHRONOUS writeFileSync on the Electron
  // main thread, 1.5 s after the fill — i.e. landing squarely inside the next
  // order burst, over and over, and scaling with every week of trading.
  // NOW: the hot path appends ONLY the newly merged rows to a journal
  // (coalesced, async, bytes proportional to the batch), and the full
  // snapshot is written rarely, asynchronously, atomically (tmp + rename) and
  // out of the burst. Recovery = snapshot + journal replay through the normal
  // exactly-once merge, so an interrupted write can lose nothing that was
  // already durable: the snapshot is never overwritten in place, and a
  // half-written journal line is dropped by lbJrnParse.
  const LB_JRN_FLUSH_MS = 250;         // journal coalescing window
  const LB_JRN_MAX_BYTES = 1 << 20;    // journal past this ⇒ fold into a snapshot
  const LB_SNAP_MS = 30000;            // ordinary snapshot debounce
  const LB_SNAP_QUIET_MS = 3000;       // ... deferred while fills keep landing
  const LB_SNAP_MAX_MS = 120000;       // ... but never past this hard deadline
  const LB_SNAP_RETRY_MS = 2000;       // failed snapshot ⇒ retry
  const LB_SNAP_WAIT_MS = 2000;        // explicit op waiting out a fold
  const lbFile = () => path.join(userDataDir(), 'local_fills_v1.json');
  const lbTmp = () => path.join(userDataDir(), 'local_fills_v1.json.tmp');
  // The journal is a SEQUENCE of segments, never one rewritten file. A
  // snapshot opens a fresh segment before it serializes and deletes the older
  // ones only once it has landed, so no journal file is ever renamed or
  // truncated under an append that may still be in flight — the whole class of
  // "the rows are in neither file for a moment" simply cannot arise.
  const LB_JRN_HARD_BYTES = 4 << 20;   // …and past this the fold cannot wait
  const LB_JRN_STALE_WARN = 8;         // covered segments still on disk ⇒ say so
  const LB_JRN_RE = /^local_fills_v1\.(\d+)\.jrn$/;
  const LB_JRN_OLD = 'local_fills_v1.jrn';   // pre-segment installs (≤ v1.5.107)
  const lbJrnF = (seq) => path.join(userDataDir(), 'local_fills_v1.' + seq + '.jrn');
  let _lbStore = null;
  let _lbJrnPend = [], _lbJrnT = null, _lbJrnBusy = false, _lbJrnBytes = 0;
  let _lbJrnSeq = 0;   // segment appends go to right now
  let _lbSnapT = null, _lbSnapDue = 0, _lbSnapMax = 0, _lbSnapBusy = false;
  let _lbSnapAgain = false, _lbLastFill = 0, _lbPersistErr = null;
  let _lbSnapWait = [];                // explicit ops waiting out a background fold
  function lbScopeIn(st, slot) {
    let sc = st.scopes[slot];
    if (!sc) sc = st.scopes[slot] = { rows: [], del: {}, bf: null };
    if (!Array.isArray(sc.rows)) sc.rows = [];
    if (!sc.del || typeof sc.del !== 'object') sc.del = {};
    return sc;
  }
  function lbLoad() {
    if (_lbStore) return _lbStore;
    let d = null;
    try { d = JSON.parse(fs.readFileSync(lbFile(), 'utf8')); } catch (e) { d = null; }
    _lbStore = (d && typeof d === 'object' && d.scopes && typeof d.scopes === 'object')
      ? d : { v: 1, scopes: {} };
    // Journal replay — every segment still on disk, oldest first. Replaying a
    // segment the snapshot already contains costs nothing (the merge is
    // exactly-once), so a segment whose delete failed can never corrupt: the
    // sweep is free to be best-effort.
    const segs = [];
    try {
      for (const f of fs.readdirSync(userDataDir())) {
        const m = LB_JRN_RE.exec(f);
        if (m) segs.push({ seq: +m[1], f: path.join(userDataDir(), f) });
      }
    } catch (e) { /* no dir yet */ }
    segs.sort((a, b) => a.seq - b.seq);
    _lbJrnSeq = segs.length ? segs[segs.length - 1].seq : 0;
    let batches = 0, rows = 0, bad = 0;
    for (const s of [{ seq: -1, f: path.join(userDataDir(), LB_JRN_OLD) }].concat(segs)) {
      let jt = null;
      try { jt = fs.readFileSync(s.f, 'utf8'); } catch (e) { continue; }
      if (!jt) continue;
      const p = lbJrnParse(jt);
      for (const b of p.batches) {
        try { rows += lbScopeMerge(lbScopeIn(_lbStore, b.slot), b.rows); } catch (e) { /* one bad batch never blocks the store */ }
      }
      batches += p.batches.length; bad += p.bad;
      if (s.seq === _lbJrnSeq) _lbJrnBytes = Buffer.byteLength(jt);
    }
    if (batches || bad) {
      tdiag('lblot', 'jrn-replay', { k: 'lb', seg: segs.length, batches,
        rows, bad, bytes: _lbJrnBytes });
      lbSnapSoon(0);   // fold the journal back into the snapshot promptly
    }
    const mig = lbMigrateBgCase(_lbStore);
    if (mig) {
      tdiag('lblot', 'bg-case-migrate', { k: 'lb', rows: mig });
      lbSnapSoon(0);
    }
    return _lbStore;
  }
  // #2251 one-time symbol-case repair. Bitget's REST fills answer with a
  // LOWER-case symbol while its WS instId is UPPER-case, so a store written
  // before the normalizers agreed holds one instrument under two spellings:
  // two replay groups that can never net to flat, and rows invisible to every
  // symbol-keyed consumer (chart triangles, break-even from local replay).
  // Safe to re-run — symbol is not part of lbFillKey, so re-casing can never
  // collide with a tombstone or a dedup key; it only re-groups. Bumping
  // `_ep` is required: a non-append mutation is invisible to the replay
  // cache's group signatures.
  function lbMigrateBgCase(st) {
    let n = 0;
    for (const slot of Object.keys((st && st.scopes) || {})) {
      const sc = st.scopes[slot];
      if (!sc || !Array.isArray(sc.rows)) continue;
      let hit = 0;
      for (const r of sc.rows) {
        if (!r || r.venue !== 'bitget') continue;
        const s = String(r.symbol || ''), u = s.toUpperCase();
        if (!s || u === s) continue;
        r.symbol = u; hit++;
      }
      if (hit) { sc._ep = (sc._ep | 0) + 1; n += hit; }
    }
    return n;
  }
  // Hot path: journal the rows that were actually added. Sites that cannot
  // hand over their batch (backfill/import merges — not the burst path) fall
  // back to the plain snapshot debounce, i.e. exactly today's behaviour.
  function lbSaveSoon(slot, rows) {
    if (slot && rows && rows.length) {
      _lbLastFill = Date.now();
      const t0 = lbT();
      lbJrnQueue(slot, rows);
      lbTap('persist.jrnline', t0);
      lbJrnArm();
      lbSnapSoon(LB_SNAP_MS);
      return;
    }
    lbSnapSoon(LB_SAVE_DEBOUNCE_MS);
  }
  function lbJrnQueue(slot, rows) {
    _lbJrnPend.push(lbJrnLine(slot, rows));
  }
  // NOTE: appends keep flowing while a snapshot is in flight. Blocking them
  // for the duration of the write would stretch a fill's exposure from the
  // coalescing window to "however long the snapshot takes" — and those rows
  // are not in that snapshot either, so a crash would lose them. They go into
  // the segment the snapshot has ALREADY moved past, which it will not delete.
  function lbJrnArm() {
    if (_lbJrnT || !_lbJrnPend.length) return;
    _lbJrnT = setTimeout(() => { _lbJrnT = null; lbJrnFlush(); }, LB_JRN_FLUSH_MS);
  }
  function lbJrnFlush() {
    if (_lbJrnBusy || !_lbJrnPend.length) return;
    const txt = _lbJrnPend.join('');
    _lbJrnPend = [];
    _lbJrnBusy = true;
    const seq = _lbJrnSeq;   // the segment THIS batch belongs to
    const t0 = lbT();
    fs.appendFile(lbJrnF(seq), txt, (err) => {
      _lbJrnBusy = false;
      lbTap('persist.jrnwrite', t0);
      if (err) {
        _lbPersistErr = String((err && err.message) || err);
        // the batch never reached the journal: put it back at the FRONT, so
        // the snapshot that follows covers it (and still has it queued if
        // that write fails too). Nothing acknowledged is ever dropped here.
        _lbJrnPend.unshift(txt);
        lbSnapSoon(0);   // journal not taking writes ⇒ fall back to a snapshot
        return;
      }
      _lbPersistErr = null;
      // a snapshot opened a new segment while this was in flight: the bytes
      // went to the old one, which that snapshot is about to sweep.
      if (seq === _lbJrnSeq) _lbJrnBytes += Buffer.byteLength(txt);
      if (_lbJrnBytes > LB_JRN_MAX_BYTES) lbSnapSoon(0);
      else lbJrnArm();
    });
  }
  // Drop the segments a LANDED snapshot has made redundant (everything up to
  // and including the one that was current when it serialized). Deliberately
  // best effort and asynchronous: an unlink that fails — Windows keeps a
  // handle busy, the file is gone already — leaves a segment that the next
  // replay simply dedupes, and the next snapshot tries again. Nothing is ever
  // deleted before the snapshot that supersedes it is on disk.
  function lbJrnSweep(upto) {
    const dir = userDataDir();
    fs.readdir(dir, (e, list) => {
      if (e || !list) return;
      let stale = 0;
      for (const f of list) {
        const m = LB_JRN_RE.exec(f);
        if (f !== LB_JRN_OLD && !(m && +m[1] <= upto)) continue;
        stale++;
        fs.unlink(path.join(dir, f), () => { /* next sweep retries */ });
      }
      // Best effort, but a directory that keeps REFUSING deletes accumulates
      // segments and slows every restart. Deleting them is the only bound that
      // does not throw fills away, so when they pile up we say so instead of
      // failing silently.
      if (stale > LB_JRN_STALE_WARN) {
        _lbPersistErr = 'journal cleanup failing: ' + stale + ' stale segments';
        tdiag('lblot', 'jrn-stale', { k: 'lb', stale, upto });
      }
    });
  }
  function lbSnapSoon(delay) {
    const now = Date.now();
    const d = Number.isFinite(delay) ? Math.max(0, delay) : LB_SNAP_MS;
    if (!_lbSnapMax) _lbSnapMax = now + LB_SNAP_MAX_MS;
    const due = now + d;
    if (_lbSnapT && _lbSnapDue && _lbSnapDue <= due) return;   // already sooner
    if (_lbSnapT) clearTimeout(_lbSnapT);
    _lbSnapDue = due;
    _lbSnapT = setTimeout(lbSnapTick, d);
  }
  function lbSnapTick() {
    _lbSnapT = null;
    const now = Date.now();
    // The whole-store stringify is ~10 ms of main loop. It waits out an active
    // fill stream — but on a deadline that is NOT re-anchored, so a permanently
    // busy account still gets its snapshot.
    // …but the wait is also capped by SIZE, not just by the deadline: a fill
    // stream that never goes quiet would otherwise grow one segment for the
    // whole two minutes, and every restart replays it synchronously. Past the
    // hard cap the fold runs mid-stream — ~10 ms of loop against an unbounded
    // startup.
    if (now < _lbSnapMax && (now - _lbLastFill) < LB_SNAP_QUIET_MS
        && _lbJrnBytes < LB_JRN_HARD_BYTES) {
      _lbSnapDue = now + LB_SNAP_QUIET_MS;
      _lbSnapT = setTimeout(lbSnapTick, LB_SNAP_QUIET_MS);
      return;
    }
    lbSnapNow(false);
  }
  // Atomic whole-store write. `sync` is for the explicit ops that report
  // persistErr to the caller (delete/import/reimport) and for quit.
  function lbSnapNow(sync) {
    if (!_lbStore) return true;
    // A second writer cannot run: the store would be serialized twice into the
    // same tmp file. A caller that needs a DEFINITIVE verdict (explicit ops,
    // quit) still gets durability — its rows go to the journal synchronously.
    // A second writer cannot run. For a background fold that is fine (the next
    // one covers it). A caller that wants a VERDICT gets its queued rows into
    // the journal and an honest `false`: the store was not written, and a
    // delete or an in-place re-import is not something a journal of appends
    // can describe. lbSaveNow waits for the in-flight write instead of ever
    // landing here.
    if (_lbSnapBusy) { _lbSnapAgain = true; if (!sync) return true; lbJrnFlushSync(); return false; }
    let json = null;
    const t0 = lbT();
    try {
      const slim = { v: 1, scopes: {} };
      for (const k of Object.keys(_lbStore.scopes)) {
        const sc = _lbStore.scopes[k];
        slim.scopes[k] = { rows: sc.rows, del: sc.del || {}, bf: sc.bf || null };
      }
      json = JSON.stringify(slim);
    } catch (e) {
      _lbPersistErr = String((e && e.message) || e);
      return false;
    }
    lbTap('persist.stringify', t0);
    // Everything queued for the journal right now is inside `json` (one
    // thread, the stringify just ran). The queued batches are only LENT to
    // this write: a failed snapshot puts them straight back (ahead of anything
    // that arrived meanwhile) so they still reach the journal, which sits on
    // top of the PREVIOUS snapshot. Dropping them here would leave those fills
    // in memory only — lost on the next crash.
    const covered = _lbJrnPend;
    _lbJrnPend = [];
    // Everything merged from here on goes to a FRESH segment, so it survives
    // the sweep this snapshot performs when it lands — and if the snapshot
    // fails, both segments simply stay. No file is touched until then.
    // Rolling is skipped when the live segment has no bytes yet: an untouched
    // segment number has no file at all, so there is nothing to supersede —
    // and a quiet app then stops minting a segment per snapshot.
    if (_lbJrnBytes) { _lbJrnSeq += 1; _lbJrnBytes = 0; }
    if (_lbJrnT) { clearTimeout(_lbJrnT); _lbJrnT = null; }
    if (_lbSnapT) { clearTimeout(_lbSnapT); _lbSnapT = null; }
    _lbSnapDue = 0; _lbSnapMax = 0;
    const done = (err) => {
      _lbSnapBusy = false;
      // wake anything waiting to write the store itself (explicit ops). These
      // are promise continuations, so they run after this frame completes —
      // never re-entrantly inside it.
      if (_lbSnapWait.length) { const w = _lbSnapWait; _lbSnapWait = []; for (const f of w) f(); }
      if (err) {
        _lbPersistErr = String((err && err.message) || err);
        try { fs.unlinkSync(lbTmp()); } catch (e) { /* best effort */ }
        if (covered.length) _lbJrnPend = covered.concat(_lbJrnPend);
        lbJrnArm();                     // durable in the journal instead
        lbSnapSoon(LB_SNAP_RETRY_MS);   // and try the snapshot again
        return false;
      }
      _lbPersistErr = null;
      // only NOW are the segments below the live one redundant. The boundary
      // is read HERE, not captured before the write: if the segment did not
      // roll (it had no bytes), the live one keeps every row appended during
      // the write.
      lbJrnSweep(_lbJrnSeq - 1);
      if (_lbSnapAgain) { _lbSnapAgain = false; lbSnapSoon(LB_SNAP_MS); }
      lbJrnArm();
      return true;
    };
    // tmp → fsync → rename: the live store is never opened for writing, so a
    // crash/force-quit mid-write leaves the PREVIOUS store intact and the
    // journal still on disk. The fsync is what makes the rename meaningful —
    // without it the directory entry can land before the bytes do.
    if (sync) {
      const t1 = lbT();
      try {
        const fd = fs.openSync(lbTmp(), 'w');
        try { fs.writeFileSync(fd, json); fs.fsyncSync(fd); }
        finally { fs.closeSync(fd); }
        fs.renameSync(lbTmp(), lbFile());
      } catch (e) { return done(e); }
      lbTap('persist.write', t1);
      return done(null);
    }
    _lbSnapBusy = true;
    const t2 = lbT();
    fs.open(lbTmp(), 'w', (eo, fd) => {
      if (eo) { done(eo); return; }
      fs.writeFile(fd, json, (e1) => {
        fs.fsync(fd, (e2) => {
          fs.close(fd, () => {
            const err = e1 || e2;
            if (err) { done(err); return; }
            fs.rename(lbTmp(), lbFile(), (e3) => { lbTap('persist.write', t2); done(e3); });
          });
        });
      });
    });
    return true;
  }
  // Explicit ops (import, delete, re-import, backfill) must return a
  // DEFINITIVE durable verdict, and only some of them are expressible as
  // journal appends: a delete, a tombstone clear or an in-place re-import is
  // not. So when a background fold is in flight, WAIT for it and then write
  // the store — never report success on the strength of a journal that cannot
  // describe the mutation. The wait is bounded (a filesystem call that never
  // returns must not hang an op): past it the write is attempted anyway and
  // its honest verdict — persistErr — reaches the caller.
  async function lbSaveNow() {
    for (let i = 0; i < 3 && _lbSnapBusy; i++) await lbSnapSettled(LB_SNAP_WAIT_MS);
    return lbSnapNow(true);
  }
  // Resolve when the in-flight snapshot settles, or after `ms` — and on the
  // timeout DROP the registration: a filesystem call that never returns must
  // not leave one closure per explicit op behind, or a late completion would
  // walk that whole queue in a single frame (the exact stall this round is
  // about).
  function lbSnapSettled(ms) {
    return new Promise((res) => {
      let t = null, fired = false;
      const fire = () => { if (fired) return; fired = true; if (t) { clearTimeout(t); t = null; } res(); };
      const w = () => fire();
      t = setTimeout(() => {
        const i = _lbSnapWait.indexOf(w);
        if (i >= 0) _lbSnapWait.splice(i, 1);
        fire();
      }, ms);
      _lbSnapWait.push(w);
    });
  }
  // Last-resort durability: put whatever is still queued into the journal
  // synchronously. Used at quit and whenever a snapshot write failed — the
  // journal sits on top of the last GOOD snapshot, so replaying it recovers
  // every acknowledged fill.
  function lbJrnFlushSync() {
    if (!_lbJrnPend.length) return true;
    const txt = _lbJrnPend.join('');
    try { fs.appendFileSync(lbJrnF(_lbJrnSeq), txt); } catch (e) {
      _lbPersistErr = String((e && e.message) || e);
      return false;
    }
    _lbJrnPend = [];
    _lbJrnBytes += Buffer.byteLength(txt);
    return true;
  }
  // Quit / exit: get whatever is only in memory onto disk, synchronously.
  function lbFlushSync() {
    try {
      if (_lbJrnT) { clearTimeout(_lbJrnT); _lbJrnT = null; }
      if (_lbSnapT) { clearTimeout(_lbSnapT); _lbSnapT = null; }
      if (!_lbStore) return true;
      // lbSnapNow(true) already falls back to a synchronous journal append
      // when it cannot write (a snapshot is in flight) — the previous snapshot
      // plus the journal segments replay every fill.
      const ok = lbSnapNow(true);
      // the snapshot failed (disk full, permissions): the batches it borrowed
      // are back in the queue, so get them into the journal before we exit —
      // the previous snapshot plus this journal still replays every fill.
      if (!ok) { lbJrnFlushSync(); return false; }
      return true;
    } catch (e) { return false; }
  }
  // Quit path, same reasoning as lbSaveNow: while a background fold is in
  // flight a synchronous flush can only APPEND to the journal, and an append
  // cannot carry a delete, a tombstone clear or an in-place re-import. So hold
  // the quit for the fold — bounded, because a quit must always finish — and
  // then write the store itself.
  async function lbFlushWait() {
    for (let i = 0; i < 2 && _lbSnapBusy; i++) await lbSnapSettled(LB_SNAP_WAIT_MS);
    const ok = lbFlushSync();
    // Past the wait the quit goes ahead either way — an app that refuses to
    // exit is a worse failure than one that says so — but it never goes ahead
    // SILENTLY: every fill is still on disk (previous snapshot + journal), and
    // this line says a mutation the journal cannot express may not be.
    if (!ok) tdiag('lblot', 'quit-unsafe', { k: 'lb', busy: _lbSnapBusy ? 1 : 0,
      err: String(_lbPersistErr || 'snapshot in flight') });
    return ok;
  }
  function lbScope(slot) { return lbScopeIn(lbLoad(), slot); }
  // Drain the live shell fill caches (kraken WS session / binance UDS
  // session) into the scope store — normalize with the engine-twin
  // normalizers, merge exactly-once. Cheap and idempotent: called from
  // every lblot_read/backfill, so panel polling IS the persistence beat.
  // #2230 cheap source signature: the VERSION of each of the venue's live
  // push rings (see lbSrcVer — a monotonic per-ring mutation counter, because
  // these rings are bounded and a push at cap leaves the length unchanged).
  // O(1) per ring, no row touched.
  function lbDrainSrcN(slot, venue) {
    const rn = (sc) => lbSrcVer(sc && sc.fills);
    if (venue === 'kraken') {
      const s = krWsSessions[slot];
      return s ? rn(s.spot) + '/' + rn(s.fut) : '-';
    }
    if (venue === 'binance') {
      const s = bnUdsSessions[slot];
      return s ? rn(s.spot) + '/' + rn(s.fut) : '-';
    }
    if (venue === 'hyperliquid') {
      const s = hlPushSessions[slot];
      return s ? rn(s.acct) : '-';
    }
    if (venue === 'bybit') {
      const s = bybPushSessions[slot];
      return s ? rn(s.acct) : '-';
    }
    if (venue === 'gate') {
      const s = gatePushSessions[slot];
      return s ? rn(s.sp) + '/' + rn(s.fu) : '-';
    }
    if (venue === 'bitget') {
      // #2246/#2247: the SAME two per-market rings carry both the paced REST
      // fills poll and the private-WS order deltas (one side-inclusive
      // tradeId seen-set), so the no-news gate and the incremental cursor
      // work exactly as they do for the push venues.
      const s = bgFillRings[slot];
      return s ? rn(s.sp) + '/' + rn(s.fu) : '-';
    }
    if (venue === 'kucoin') {
      // #2272: the SAME two per-market rings carry the paced REST fills poll
      // and the private-WS fee catch-up (one side-inclusive tradeId|side
      // seen-set), so the no-news gate and the incremental cursor work
      // exactly as they do for the push venues.
      const s = kcFillRings[slot];
      return s ? rn(s.sp) + '/' + rn(s.fu) : '-';
    }
    return '-';
  }
  const _lbDrainAt = {};    // slot → { t, sig } (#2230 no-news gate)
  const _lbDrainCur = {};   // slot → { r: {ring: rev}, skip, full } (#2234)
  const LB_DRAIN_RETRY_MS = 3000;   // re-try rows no normalizer could take yet
  function lbDrain(slot, venue) {
    const sc = lbScope(slot);
    // #2230: nothing new upstream ⇒ this drain provably merges nothing. Skip
    // the whole normalize+merge pass so N windows polling the same slot in
    // the same beat cost ONE of them.
    // #2234: the store LENGTH is no longer part of the signature. It made
    // every successful merge invalidate the gate, so each merged fill bought
    // a second full normalize pass on the very next poll — the gate could not
    // tell "the store changed because we just merged" from "there is new
    // upstream data". Store mutations a drain really must react to
    // (delete / prune / tombstone clear) reset the gate through lbStoreMut.
    const _dsig = lbDrainSrcN(slot, venue);
    const _dnow = Date.now();
    if (lbDrainSkip(_lbDrainAt[slot], _dsig, _dnow, LB_DRAIN_IDLE_MS)) return 0;
    _lbDrainAt[slot] = { t: _dnow, sig: _dsig };
    const aid = (() => {
      const sn = tnSlotNorm(slot);
      const m = sn && sn.slot !== sn.base ? /#a(\d+)$/.exec(sn.slot) : null;
      return m ? parseInt(m[1], 10) : 0;
    })();
    // #2234 INCREMENTAL: normalize only the rows each ring has pushed since
    // the last drain, instead of re-normalizing all 400-600 cached rows of
    // every ring on every poll. `retry` forces a whole-ring pass when the
    // previous pass left rows it could not normalize yet (HL '@N' spot coins,
    // gate contracts awaiting a multiplier) — that self-healing must keep
    // happening — and lbRingFrom falls back to the whole ring by itself on a
    // first drain, a ring reset/reconnect, or cap eviction.
    let cur = _lbDrainCur[slot];
    if (!cur) cur = _lbDrainCur[slot] = { r: {}, skip: 0, full: 0 };
    const retry = cur.skip > 0 && (_dnow - (cur.full || 0)) >= LB_DRAIN_RETRY_MS;
    if (retry) cur.full = _dnow;
    const tNorm = lbT();
    const fills = [];
    let skipped = 0, scanned = 0;
    const ring = (id, F, fn) => {
      if (!F || !Array.isArray(F.rows)) return;
      const rows = F.rows;
      const from = lbRingFrom(cur.r[id], F.rev | 0, rows.length, retry);
      for (let i = from; i < rows.length; i++) {
        const f = fn(rows[i]);
        if (f) fills.push(f); else skipped++;
      }
      scanned += rows.length - from;
      cur.r[id] = F.rev | 0;
    };
    if (venue === 'kraken') {
      const sess = krWsSessions[slot];
      if (sess) {
        ring('kr.spot', sess.spot.fills, (r) => lbNormKrWsSpot(r.raw));
        ring('kr.fut', sess.fut.fills, (r) => lbNormKrWsFut(r.raw));
      }
    } else if (venue === 'binance') {
      const sess = bnUdsSessions[slot];
      if (sess) {
        ring('bn.spot', sess.spot.fills, (r) => lbNormBnSpot(r));
        ring('bn.fut', sess.fut.fills, (r) => lbNormBnFut(r, r.T));
      }
    } else if (venue === 'hyperliquid') {
      // #2012: the push session caches RAW userFills rows (account-level —
      // spot + main-dex + HIP-3 all ride one stream). Spot wire coins map
      // via hlProds.wireMap when warm, else pass through raw (engine
      // parity); the drain is idempotent so a later drain re-normalizes
      // nothing — rows merged once by exec_id stay merged.
      const sess = hlPushSessions[slot];
      if (sess) {
        const wm = hlProds.wireMap || {};
        ring('hl.acct', sess.acct.fills, (r) => lbNormHlFill(r, wm));
      }
    } else if (venue === 'bybit') {
      // #2051: the push session caches RAW V5 execution rows (account-level —
      // linear + spot ride one stream, rows carry `category`). The drain is
      // idempotent: rows merged once by exec_id stay merged.
      const sess = bybPushSessions[slot];
      if (sess) ring('byb.acct', sess.acct.fills, (r) => lbNormBybFill(r));
    } else if (venue === 'gate') {
      // #2153: two per-market raw rings (spot/futures sockets never mix).
      // Futures rows size in CONTRACTS — quanto_multiplier from the shell
      // contract cache; a cold entry skips the row THIS drain and fires a
      // best-effort warm (HL wireMap recipe: the raw row stays cached, the
      // retry sweep re-normalizes it once the multiplier landed).
      const sess = gatePushSessions[slot];
      if (sess) {
        ring('gate.sp', sess.sp.fills, (r) => lbNormGateFill(r, 'spot', null));
        ring('gate.fu', sess.fu.fills, (r) => {
          const sym = String((r && r.contract) || '');
          const mc = gateMultCache[sym];
          const mult = mc ? mc.v : null;
          if (!(Number(mult) > 0)) {
            if (sym) gateMult(sym, sess.route).catch(() => { /* warm */ });
            return null;
          }
          return lbNormGateFill(r, 'futures', mult);
        });
      }
    } else if (venue === 'bitget') {
      // #2246: two per-market REST-poll rings (lbBgLive). Rows are RAW
      // venue fill rows — the market comes from the RING, never from the
      // row, because a Bitget spot and a mix fill row are shape-identical.
      const R = bgFillRings[slot];
      if (R) {
        ring('bg.sp', R.sp, (r) => lbNormBitgetFill(r, 'spot'));
        ring('bg.fu', R.fu, (r) => lbNormBitgetFill(r, 'futures'));
      }
    } else if (venue === 'kucoin') {
      // #2272: two per-market REST-poll rings (lbKcLive). Rows are RAW venue
      // fill rows — the market comes from the RING, never from the row,
      // because a KuCoin spot and futures fill row are shape-identical.
      // Futures rows size in CONTRACTS: the multiplier comes from the shell
      // contract cache, and a cold entry skips the row THIS drain and fires a
      // best-effort warm (gate/HL recipe — the raw row stays cached and the
      // retry sweep re-normalizes it once the multiplier landed). Storing a
      // contract count as a coin quantity would replay a 100× position.
      const R = kcFillRings[slot];
      if (R) {
        ring('kc.sp', R.sp, (r) => lbNormKucoinFill(r, 'spot', null));
        ring('kc.fu', R.fu, (r) => {
          const sym = String((r && r.symbol) || '');
          const mc = kcMultCache[sym];
          const mult = mc ? mc.v : null;
          if (!(Number(mult) > 0)) {
            if (sym) kcMult(sym, R.route).catch(() => { /* warm */ });
            return null;
          }
          return lbNormKucoinFill(r, 'futures', mult);
        });
      }
    }
    cur.skip = skipped;
    if (aid) for (const f of fills) f.aid = aid;
    lbTap('drain.normalize', tNorm);
    // #1973 field-test diag: pre-compute which drained rows are NEW (a ring
    // re-serves rows the cursor already covered after a retry sweep, so
    // `fills.length` alone is not a batch). Diag-only, skipped when the seen
    // index isn't built yet.
    let newIds = null;
    if (diagTap && sc.seen) {
      newIds = [];
      for (const f of fills) {
        const k = lbFillKey(f);
        if (k && !sc.seen[k] && !(sc.del && (sc.del[k] || sc.del[lbFillKeyLegacy(f)])))
          newIds.push(String(f.exec_id || k));
      }
    }
    const tMerge = lbT();
    const addRows = [];
    const srt0 = sc._srt | 0;
    const added = lbScopeMerge(sc, fills, addRows);
    lbTap('drain.merge', tMerge);
    if ((sc._srt | 0) !== srt0) lbPerfSort();
    if (added) {
      // one line per live drain batch that actually merged rows — venue,
      // source, count, first/last exec id, store total. Never per empty poll.
      tdiag('lblot', 'ingest', { k: slot, v: venue, src: 'ws-drain', n: added,
        first: newIds && newIds.length ? newIds[0] : undefined,
        last: newIds && newIds.length ? newIds[newIds.length - 1] : undefined,
        total: sc.rows.length, scan: scanned, skip: skipped });
      if (sc.rows.length > LB_ROWS_CAP) lbPruneTap(slot, venue, sc);
      lbSaveSoon(slot, addRows);
    }
    return added;
  }
  function lbVenueOk(venue) { return venue === 'kraken' || venue === 'binance' || venue === 'hyperliquid' || venue === 'bybit' || venue === 'gate' || venue === 'bitget' || venue === 'kucoin'; }
  // #2012 HL spot symbol map warm-up: best-effort, TTL-cached, never fatal —
  // an unmapped '@N' spot coin stores raw this drain and self-heals on the
  // next one (drain re-normalizes the cached raw rows every poll).
  async function lbHlWarm(venue, route) {
    if (venue !== 'hyperliquid') return;
    try { await hlEnsureProducts(routeNorm(route)); } catch (e) { /* best-effort */ }
  }
  async function execLblotRead(intent) {
    const venue = String(intent.venue || '');
    if (!lbVenueOk(venue)) return { ok: false, message: 'local blotter not supported for this venue' };
    const slot = String(intent.credSlot || venue);
    await lbHlWarm(venue, intent.route);
    await lbBgLive(venue, slot, intent.route);   // #2246 Bitget REST live lane
    await lbKcLive(venue, slot, intent.route);   // #2272 KuCoin REST live lane
    const added = lbDrain(slot, venue);
    const sc = lbScope(slot);
    const t0 = lbT();
    // #2234 BOUNDED REPLY: a read used to hand back the ENTIRE store, and the
    // reply is structured-cloned per window — the 24 reads 14 starting windows
    // fire are what the field log's two boot stalls (0.46 s, 7.27 s) are made
    // of. Callers now say what they need: a ts window (`since`/`until`), a
    // newest-N cap (`limit`), or the shared serialized form (`wantJson` — one
    // string built once, ~30× cheaper to clone than a 14k-object graph, and
    // parsed in the renderer's own process). No selector ⇒ unchanged reply.
    let rows = sc.rows;
    const since = Number(intent.since) || 0;
    const until = Number(intent.until) || 0;
    if (since > 0 || until > 0) {
      rows = rows.filter((r) => {
        const ts = Number(r.ts) || 0;
        return (!since || ts >= since) && (!until || ts <= until);
      });
    }
    const limit = Math.floor(Number(intent.limit) || 0);
    if (limit > 0 && rows.length > limit) rows = rows.slice(rows.length - limit);
    const out = {
      ok: true, added: added, count: sc.rows.length, n: rows.length,
      hwm: { spot: lbHwm(sc.rows, 'spot'), futures: lbHwm(sc.rows, 'futures') },
      bf: sc.bf || null,
    };
    if (intent.wantJson) out.fillsJson = JSON.stringify(rows);
    else out.fills = rows;
    lbTap('read.reply', t0);
    return out;
  }
  async function execLblotIngest(intent) {
    // Explicit merge of NORMALIZED fills (server "Import" / panel-supplied
    // rows). Venue must match; rows are whitelisted before storage.
    const venue = String(intent.venue || '');
    if (!lbVenueOk(venue)) return { ok: false, message: 'local blotter not supported for this venue' };
    const slot = String(intent.credSlot || venue);
    const rowsIn = Array.isArray(intent.fills) ? intent.fills : [];
    if (rowsIn.length > 60000) return { ok: false, message: 'too many rows' };
    const fills = [];
    for (const r of rowsIn) {
      if (!r || typeof r !== 'object') continue;
      if (String(r.venue || '') !== venue) continue;
      const f = {
        venue: venue,
        market: String(r.market || ''), symbol: String(r.symbol || ''),
        side: String(r.side || ''), posSide: String(r.posSide || ''),
        order_px: String(r.order_px || ''), exec_px: String(r.exec_px || ''),
        qty: String(r.qty || ''), value: String(r.value || ''),
        fee: String(r.fee || '0'), closed_pnl: String(r.closed_pnl || '0'),
        ts: Math.floor(Number(r.ts) || 0), exec_id: String(r.exec_id || ''),
      };
      if (r.order_id != null) f.order_id = String(r.order_id);
      if (r.kind != null) f.kind = String(r.kind);
      if (r.funding != null) f.funding = String(r.funding);
      if (r.type != null) f.type = String(r.type);
      if (r.fee_alt) f.fee_alt = String(r.fee_alt);
      fills.push(f);
    }
    // Rows adopt the SLOT's account id (never a caller-supplied aid): the
    // scope store is per-account, a mismatched aid would leak rows across
    // account replays.
    const slotAid = (() => {
      const m = /#a(\d+)$/.exec(slot);
      return m ? parseInt(m[1], 10) : 0;
    })();
    if (slotAid) for (const f of fills) f.aid = slotAid;
    const sc = lbScope(slot);
    const addRows = [];
    const added = lbScopeMerge(sc, fills, addRows);
    if (sc.rows.length > LB_ROWS_CAP) lbPruneTap(slot, venue, sc);
    // Queue the added rows for the journal FIRST: if a background snapshot is
    // in flight this op cannot write the store, and the journal is then what
    // makes the import durable (lbSnapNow flushes it synchronously and still
    // reports an honest verdict). A snapshot that does run folds them in.
    if (added) lbJrnQueue(slot, addRows);
    const saved = await lbSaveNow();   // explicit op: snapshot now, journal folded in
    // #1973: explicit ingest flow (panel Import button / supplied rows)
    tdiag('lblot', 'ingest', { k: slot, v: venue, src: 'import', recv: rowsIn.length,
      n: added, dedup: fills.length - added, total: sc.rows.length,
      persistErr: saved ? undefined : 1 });
    return { ok: true, added: added, count: sc.rows.length,
             ...(saved ? {} : { persistErr: true }) };
  }
  async function execLblotDelete(intent) {
    // OFFLINE delete: tombstone + remove locally. Server tombstones
    // reconcile only at explicit save/import — never automatically.
    const venue = String(intent.venue || '');
    if (!lbVenueOk(venue)) return { ok: false, message: 'local blotter not supported for this venue' };
    const slot = String(intent.credSlot || venue);
    const keys = Array.isArray(intent.keys) ? intent.keys.map(String).slice(0, 5000) : [];
    if (!keys.length) return { ok: false, message: 'no keys' };
    const sc = lbScope(slot);
    const now = Date.now();
    const set = {};
    for (const k of keys) { set[k] = 1; sc.del[k] = now; }
    const before = sc.rows.length;
    sc.rows = sc.rows.filter((r) => !set[lbFillKey(r)]);
    sc.seen = null;
    lbStoreMut(slot, sc);   // #2234 rows removed from the middle — bust caches
    const saved = await lbSaveNow();
    return { ok: true, removed: before - sc.rows.length,
             ...(saved ? {} : { persistErr: true }) };
  }
  // #2193 replay cache: the 2s panel poll re-ran lbSpotQuar + lbReconstruct
  // over the ENTIRE persisted store on every read even when nothing changed
  // (added:0) — with a re-import-grown 14k-fill store that full replay per
  // beat × per window was the ~5s stutter's main-process half. Cache the
  // reconstructed trades per slot keyed by the rows ARRAY IDENTITY + length
  // (every mutator either pushes in place — length changes — or reassigns
  // sc.rows: delete/prune/quarantine-clear all swap the reference), so a
  // no-news read is O(1). `rev` bumps on every recompute; readers that pass
  // their known rev back get {unchanged:true} with NO trades payload (skips
  // the IPC serialization of every trade row per poll per window).
  // displayMap is only applied at recompute; poll paths pass none.
  const _lbTrCache = {};
  let _lbTrRev = 0;
  async function execLblotTrades(intent) {
    // Drain + replay: the local fills → OPEN/CLOSED trade rows via the
    // engine-twin lbReconstruct (grouping parity test-guarded). One replay
    // implementation shell-side = every window/pop-out renders the same
    // truth. `keys` on each row = contributing fill keys (offline delete).
    const venue = String(intent.venue || '');
    if (!lbVenueOk(venue)) return { ok: false, message: 'local blotter not supported for this venue' };
    const slot = String(intent.credSlot || venue);
    await lbHlWarm(venue, intent.route);
    await lbBgLive(venue, slot, intent.route);   // #2246 Bitget REST live lane
    await lbKcLive(venue, slot, intent.route);   // #2272 KuCoin REST live lane
    const added = lbDrain(slot, venue);
    const sc = lbScope(slot);
    const dmSig = intent.displayMap ? JSON.stringify(intent.displayMap) : '';
    // #2230 one serialization for the whole app. Every open window polls this
    // op, and a fill invalidates the rev in all of them at once (push kick) —
    // so main used to structured-clone the ENTIRE replayed trade list once per
    // window (measured: ~9 ms × 14 windows ≈ 110 ms of blocked loop per fill,
    // the recurring 273-444 ms freeze the 2026-08-15 field log caught). With
    // `wantJson` the shell stringifies the payload ONCE per rev and ships that
    // one string; cloning a string is ~30× cheaper than cloning the object
    // graph, and each renderer parses it in ITS OWN process, off this loop.
    // Opt-in, so an older panel keeps getting the object shape verbatim.
    const wantJson = !!(intent && intent.wantJson);
    const pack = (h) => {
      if (!wantJson) return { trades: h.trades, quar: h.quar };
      if (h.tj == null) h.tj = JSON.stringify(h.trades || []);
      if (h.qj == null) h.qj = JSON.stringify(h.quar || []);
      return { tradesJson: h.tj, quarJson: h.qj };
    };
    const hit = _lbTrCache[slot];
    if (hit && hit.rows === sc.rows && hit.len === sc.rows.length &&
        hit.dmSig === dmSig) {
      if ((intent.haveRev | 0) === hit.rev) {
        return { ok: true, unchanged: true, rev: hit.rev, added: added,
                 count: sc.rows.length, bf: sc.bf || null };
      }
      return Object.assign({ ok: true, rev: hit.rev, added: added, count: sc.rows.length,
                             hwm: hit.hwm, bf: sc.bf || null }, pack(hit));
    }
    let trades, quar, tj;
    try {
      // #2038 spot truncated-history quarantine BEFORE the replay: a spot
      // scope whose sum goes negative provably starts mid-position — the
      // incomplete prefix hides behind an honest ⚠ marker (engine #1849
      // parity), never a phantom OPEN group that swallows new round trips.
      const tq = lbT();
      const vis = lbSpotQuar(sc.rows);
      quar = vis.quar;
      lbTap('replay.quar', tq);
      // #2234 PER-GROUP MEMOIZED REPLAY — the freeze itself. lbReconstruct is
      // O(store) (130 ms measured on the 14.4k-row field store) and ran on
      // EVERY fill, because a merge moves rows.length and busts the cache
      // above. A fill only ever touches one (venue|market|symbol|aid) group,
      // so only that group is replayed and re-serialized; the rest is reused
      // verbatim. lbReplay's output is identical to lbReconstruct's.
      const tr = lbT();
      if (sc._rep && sc._rep.ep !== (sc._ep | 0)) sc._rep = null;
      if (!sc._rep) sc._rep = { ep: sc._ep | 0, g: Object.create(null) };
      const rp = lbReplay(sc._rep, vis.rows, intent.displayMap || null, dmSig, wantJson);
      trades = rp.trades; tj = rp.tj;
      lbTap('replay.build', tr);
      if (rp.recomputed) {
        tdiag('lblot', 'replay', { k: slot, v: venue, grp: rp.groups,
          re: rp.recomputed, rows: rp.replayed, of: vis.rows.length });
      }
      // #2098 silent-drop diag: any quarantine that hides rows leaves a tap
      // (once per distinct quar set per slot — reads poll every ~2s).
      try {
        const sig = (quar && quar.length)
          ? JSON.stringify(quar.map((q) => [q.venue, q.symbol, q.aid, q.before, q.hidden]))
          : '';
        if (sig !== (_lbQuarSig[slot] || '')) {
          _lbQuarSig[slot] = sig;
          for (const q of (quar || [])) {
            tdiag('lblot', 'quar', { k: slot, v: q.venue, s: q.symbol,
              aid: q.aid || undefined, n: q.hidden, before: q.before,
              reason: 'neg-replay' });
          }
        }
      } catch (e) { /* diag only */ }
    }
    catch (e) { return { ok: false, message: 'replay failed: ' + ((e && e.message) || 'error') }; }
    const hwm = { spot: lbHwm(sc.rows, 'spot'), futures: lbHwm(sc.rows, 'futures') };
    // `tj` comes straight out of lbReplay when the caller wanted JSON — it is
    // assembled from the per-group fragments, so a fill re-stringifies one
    // group instead of the whole 1.8 MB payload (#2234).
    _lbTrCache[slot] = { rows: sc.rows, len: sc.rows.length, dmSig: dmSig,
                         rev: ++_lbTrRev, trades: trades, quar: quar || [],
                         hwm: hwm, tj: tj == null ? null : tj, qj: null };
    return Object.assign({ ok: true, rev: _lbTrCache[slot].rev, added: added,
                           count: sc.rows.length, hwm: hwm, bf: sc.bf || null },
                         pack(_lbTrCache[slot]));
  }
  // Startup/arm gap backfill: "all fills since my newest locally-recorded
  // fill", per market, straight from the exchange with the device key.
  // Single-flight; result (incl. an explicit possible-gap flag when the
  // lookback horizon is exceeded or there is no local watermark) is stamped
  // on the scope (`bf`) so every window/pop-out can surface it.
  const LB_BF_OVERLAP_MS = 10 * 60 * 1000;   // re-fetch overlap — dedupe absorbs it
  const LB_BF_DEFAULT_MS = 7 * 86400 * 1000; // empty store: last 7d + gap note
  let _lbBfBusy = {};
  async function execLblotBackfill(intent) {
    const venue = String(intent.venue || '');
    if (!lbVenueOk(venue)) return { ok: false, message: 'local blotter not supported for this venue' };
    const slot = String(intent.credSlot || venue);
    if (_lbBfBusy[slot]) return { ok: false, message: 'backfill already in flight', busy: true };
    _lbBfBusy[slot] = true;
    try {
      const creds = credsGet(slot);
      if (!creds) {
        tdiag('lblot', 'backfill', { k: slot, v: venue, ok: 0, err: 'no device key' });   // #1973
        return { ok: false, message: 'No API key on this device — provision Native trading first' };
      }
      const route = routeNorm(intent.route);
      lbDrain(slot, venue);
      const sc = lbScope(slot);
      const now = Date.now();
      // #1973 field-test diag: high-water marks the backfill windows anchor on
      const _dgHwmS = lbHwm(sc.rows.filter((f) => f.market === 'spot'), null);
      const _dgHwmF = lbHwm(sc.rows.filter((f) => f.market === 'futures'), null);
      let _dgFetched = 0;   // #1973 rows returned by the venue fetch (pre-dedupe)
      // #2167 gate-only: RAW per-leg row counts (pre-normalize) — `fetched`
      // counts post-normalize fills, which hid a normalizer that nulled
      // every futures row. futRows>0 with zero futures fills is now visible.
      let _dgFutRows, _dgSpotRows;
      let _dgBgAsk;   // #2251 bitget-only: windows/pages actually asked per market
      let gap = false;
      let covOk = true;
      const notes = [];
      // PER-MARKET windows: a recent fill in one market must never shorten
      // the other market's backfill window (a futures-only store would
      // silently skip older spot history otherwise).
      const bfFrm = (market, label) => {
        const hwm = lbHwm(sc.rows.filter((f) => f.market === market), null);
        if (!(hwm > 0)) {
          gap = true;
          notes.push('no local ' + label + ' history — fetched the last 7 days only');
          return now - LB_BF_DEFAULT_MS;
        }
        let f0 = hwm - LB_BF_OVERLAP_MS;
        if (f0 < now - HB_MAX_SPAN_MS) {
          f0 = now - HB_MAX_SPAN_MS + 60000;
          gap = true;
          notes.push('local ' + label + ' history older than the venue lookback horizon — a gap is possible');
        }
        return f0;
      };
      let added = 0;
      if (venue === 'kraken') {
        // one venue-wide time-window fetch covers BOTH markets → take the
        // older of the two per-market windows (full coverage either way).
        const frm = Math.min(bfFrm('spot', 'spot'), bfFrm('futures', 'futures'));
        // #1975 budget-aware: a kr_budget deferral at startup is "wait and
        // retry", never a one-shot failure (bounded — honest fail past it).
        const r = await lbKrBackfillRetry(hbKraken,
          { credSlot: slot, route: intent.route, market: 'both', frm: frm, to: now },
          (ms) => new Promise((rs) => setTimeout(rs, ms)),
          (attempt, waitMs) => tdiag('lblot', 'backfill', { k: slot, v: venue,
            act: 'kr_budget_defer', attempt: attempt, waitMs: waitMs }),
          krResvFor(slot));   // #2168: reservation spans attempts + sleeps
        if (r.bfTries > 1) notes.push('kraken rate budget deferred — ' + r.bfTries + ' attempts');
        if (!r.ok) {
          sc.bf = { ts: now, ok: false, msg: r.message || 'backfill failed' };
          lbSaveSoon();
          tdiag('lblot', 'backfill', { k: slot, v: venue, ok: 0, ms: Date.now() - now,
            err: String(r.message || 'backfill failed') });   // #1973
          return { ok: false, message: r.message || 'backfill failed' };
        }
        const fills = [];
        for (const e of (r.spot || [])) { const f = lbNormKrWsSpot(e); if (f) fills.push(f); }
        for (const e of (r.futures || [])) { const f = lbNormKrWsFut(e); if (f) fills.push(f); }
        _dgFetched = fills.length;   // #1973
        added = lbScopeMerge(sc, fills);
      } else if (venue === 'hyperliquid') {
        // #2012: ONE account-wide userFillsByTime pager covers spot +
        // main-dex futures + HIP-3 (fills are account-level on HL). The
        // subscribe/read address is the MASTER (agent keys get no history) —
        // a failed userRole probe is an honest backfill failure, never a
        // silent agent-address fetch that returns empty.
        let addr;
        try { addr = await hlMasterResolve(String(creds.key).trim(), route); }
        catch (e) {
          const msg = 'Hyperliquid master resolve failed: ' + ((e && e.message) || 'error');
          sc.bf = { ts: now, ok: false, msg: msg };
          lbSaveSoon();
          tdiag('lblot', 'backfill', { k: slot, v: venue, ok: 0, ms: Date.now() - now, err: msg });
          return { ok: false, message: msg };
        }
        // spot symbol map: best-effort — missing map stores wire names
        // (engine parity) but coverage stays honest via a note.
        const wmErr = await hlEnsureProducts(route);
        if (wmErr) notes.push('spot symbol map unavailable — spot fills keep wire names until it loads');
        const frm = Math.min(bfFrm('spot', 'spot'), bfFrm('futures', 'futures'));
        // HL caps userFillsByTime at 2000 rows/page — page forward by time,
        // bounded pages; hitting the bound = explicit possible-gap verdict.
        const HL_BF_PAGE_CAP = 8;
        const raw = [];
        const seen = {};   // exec-id dedupe for boundary-ms overlap pages
        let cur = Math.max(0, Math.floor(frm));
        let pages = 0;
        for (;;) {
          const rp = await hlInfo({ type: 'userFillsByTime', user: addr,
                                    startTime: cur, endTime: now,
                                    aggregateByTime: false }, route);
          if (!rp.ok) {
            const msg = rp.message || 'Hyperliquid fills fetch failed';
            sc.bf = { ts: now, ok: false, msg: msg };
            lbSaveSoon();
            tdiag('lblot', 'backfill', { k: slot, v: venue, ok: 0, ms: Date.now() - now, err: String(msg) });
            return { ok: false, message: msg };
          }
          const rows = Array.isArray(rp.data) ? rp.data : [];
          const stp = lbHlPageStep(rows, cur, seen, raw);
          pages++;
          if (stp.gap) {
            // a FULL page whose rows all share the start millisecond: paging
            // by time cannot prove progress — honest possible-gap verdict,
            // never a silent success (fills past this ms would be skipped).
            gap = true;
            notes.push('fill page stalled on one timestamp — a gap is possible');
          }
          if (stp.done) break;
          cur = stp.next;
          if (pages >= HL_BF_PAGE_CAP) {
            gap = true;
            notes.push('fill history page cap reached — a gap is possible');
            break;
          }
        }
        const fills = [];
        const wm = hlProds.wireMap || {};
        for (const f of raw) { const n = lbNormHlFill(f, wm); if (n) fills.push(n); }
        _dgFetched = fills.length;
        added = lbScopeMerge(sc, fills);
      } else if (venue === 'bybit') {
        // #2051: cursor-paged /v5/execution/list per category. Bybit caps
        // each query span at 7 days — the window walks forward in ≤7d chunks
        // from the per-market watermark, cursor pages inside each chunk.
        // Bounded pages; hitting the bound = explicit possible-gap verdict.
        const BYB_BF_SPAN_MS = 7 * 86400 * 1000 - 60000;
        const BYB_BF_PAGE_CAP = 60;   // across both categories
        let pages = 0;
        const raw = [];
        let failMsg = null;
        for (const cat of ['linear', 'spot']) {
          const mkt = cat === 'spot' ? 'spot' : 'futures';
          const frm = bfFrm(mkt, mkt);
          let w0 = Math.max(0, Math.floor(frm));
          while (w0 < now && pages < BYB_BF_PAGE_CAP && !failMsg) {
            const w1 = Math.min(now, w0 + BYB_BF_SPAN_MS);
            let cursor = '';
            for (;;) {
              const params = [['category', cat], ['startTime', String(w0)],
                              ['endTime', String(w1)], ['limit', '100']];
              if (cursor) params.push(['cursor', cursor]);
              const rp = await bybRequest(creds, 'GET', '/v5/execution/list',
                                          params, null, route);
              pages++;
              if (!rp.ok) { failMsg = rp.message || 'Bybit fills fetch failed'; break; }
              const res = ((rp.data || {}).result) || {};
              for (const f of res.list || []) {
                if (f && !f.category) f.category = cat;   // REST rows may omit it
                raw.push(f);
              }
              cursor = String(res.nextPageCursor || '');
              if (!cursor || !(res.list || []).length) break;
              if (pages >= BYB_BF_PAGE_CAP) {
                gap = true;
                notes.push('fill history page cap reached — a gap is possible');
                break;
              }
            }
            w0 = w1;
          }
          if (failMsg) break;
          if (w0 < now && pages >= BYB_BF_PAGE_CAP && !gap) {
            gap = true;
            notes.push('fill history page cap reached — a gap is possible');
          }
        }
        if (failMsg) {
          sc.bf = { ts: now, ok: false, msg: failMsg };
          lbSaveSoon();
          tdiag('lblot', 'backfill', { k: slot, v: venue, ok: 0, ms: Date.now() - now, err: String(failMsg) });
          return { ok: false, message: failMsg };
        }
        const fills = [];
        for (const f of raw) { const n = lbNormBybFill(f); if (n) fills.push(n); }
        _dgFetched = fills.length;
        added = lbScopeMerge(sc, fills);
      } else if (venue === 'gate') {
        // #2153: futures /futures/usdt/my_trades_timerange (from/to SECONDS,
        // offset paging, account-wide — engine _fut_fills_walk twin) + spot
        // /spot/my_trades windowed walk (docs: a no-param call serves 7d
        // only; explicit windows ≤30d; the range filters by ORDER END time;
        // page cap limit×(page-1) ≤ 1000 ⇒ at limit=1000 only two pages — a
        // full second page HALVES the window; ≥1h floor = honest gap note).
        // Futures rows size in contracts → per-contract quanto_multiplier
        // warms before normalize (engine ct_map parity).
        const GATE_BF_PAGE_CAP = 60;
        let pages = 0;
        let failMsg = null;
        const rawFut = [];
        const rawSpot = [];
        const futFrm = bfFrm('futures', 'futures');
        let off = 0;
        for (;;) {
          if (pages >= GATE_BF_PAGE_CAP) { gap = true; notes.push('futures fill page cap reached — a gap is possible'); break; }
          if (pages) await new Promise((rs) => setTimeout(rs, HB_PAGE_GAP_MS));
          const rp = await gateRequest(creds, 'GET', '/futures/usdt/my_trades_timerange',
            [['from', String(Math.floor(futFrm / 1000))], ['to', String(Math.ceil(now / 1000))],
             ['limit', '100'], ['offset', String(off)]], null, route);
          pages++;
          if (!rp.ok) {
            // spot-only key: no futures account is a normal state (the spot
            // leg still runs); anything else is an honest fetch failure.
            if (String(rp.message || '').indexOf('futures account') >= 0) break;
            failMsg = rp.message || 'Gate futures fills fetch failed';
            break;
          }
          const rows = Array.isArray(rp.data) ? rp.data : [];
          for (const f of rows) rawFut.push(f);
          if (rows.length < 100) break;
          off += rows.length;
        }
        if (!failMsg) {
          const spotFrm = bfFrm('spot', 'spot');
          const GATE_SPOT_SPAN_MAX = 29 * 86400 * 1000;
          let w0 = Math.max(0, Math.floor(spotFrm));
          let span = GATE_SPOT_SPAN_MAX;
          while (w0 < now) {
            if (pages >= GATE_BF_PAGE_CAP) { gap = true; notes.push('spot fill page cap reached — a gap is possible'); break; }
            const w1 = Math.min(now, w0 + span);
            let full2 = false;
            for (let pg = 1; pg <= 2; pg++) {
              if (pages) await new Promise((rs) => setTimeout(rs, HB_PAGE_GAP_MS));
              const rp = await gateRequest(creds, 'GET', '/spot/my_trades',
                [['from', String(Math.floor(w0 / 1000))], ['to', String(Math.ceil(w1 / 1000))],
                 ['limit', '1000'], ['page', String(pg)]], null, route);
              pages++;
              if (!rp.ok) { failMsg = rp.message || 'Gate spot fills fetch failed'; break; }
              const rows = Array.isArray(rp.data) ? rp.data : [];
              for (const f of rows) rawSpot.push(f);
              if (rows.length < 1000) break;
              if (pg === 2) full2 = true;
            }
            if (failMsg) break;
            if (full2) {
              // window truncated at the venue page cap — halve until it fits
              // (already-fetched rows re-normalize; the merge dedups them)
              if (w1 - w0 <= 3600 * 1000) {
                gap = true;
                notes.push('spot fills denser than the page cap in one hour — a gap is possible');
                w0 = w1 + 1;
              } else span = Math.max(3600 * 1000, Math.floor((w1 - w0) / 2));
              continue;
            }
            w0 = w1 + 1;
          }
        }
        if (failMsg) {
          sc.bf = { ts: now, ok: false, msg: failMsg };
          lbSaveSoon();
          tdiag('lblot', 'backfill', { k: slot, v: venue, ok: 0, ms: Date.now() - now, err: String(failMsg) });
          return { ok: false, message: failMsg };
        }
        const mset = {};
        for (const f of rawFut) { const cs = String((f && f.contract) || ''); if (cs) mset[cs] = 1; }
        for (const cs of Object.keys(mset)) { try { await gateMult(cs, route); } catch (e) { /* noted below */ } }
        let multMiss = 0;
        const fills = [];
        for (const f of rawFut) {
          const cs = String((f && f.contract) || '');
          const mc = gateMultCache[cs];
          const n = lbNormGateFill(f, 'futures', mc ? mc.v : null);
          if (n) fills.push(n);
          else if (cs && !(mc && Number(mc.v) > 0)) multMiss++;
        }
        if (multMiss) {
          gap = true;
          notes.push('contract spec unavailable for ' + multMiss + ' futures fill(s) — they retry next backfill');
        }
        for (const f of rawSpot) { const n = lbNormGateFill(f, 'spot', null); if (n) fills.push(n); }
        _dgFutRows = rawFut.length;
        _dgSpotRows = rawSpot.length;
        _dgFetched = fills.length;
        added = lbScopeMerge(sc, fills);
      } else if (venue === 'bitget') {
        // #2246: account-wide cursor walks over BOTH fill endpoints (engine
        // BitgetHistory._fills_walk twin). There is no symbol universe to
        // resolve — coverage hinges purely on the call/page caps, so ANY cap
        // hit or overflowing page reports covOk:false and the panel keeps
        // the server blotter instead of activating on a partial history.
        // Chunked into ≤7-day windows (the engine's proven span) with
        // PER-MARKET windows: one shared high-water mark would let a recent
        // futures fill truncate the spot window.
        const BG_BF_SPAN_MS = 7 * 86400 * 1000 - 60000;
        const BG_BF_CALL_CAP = 60;
        const BG_BF_CHUNK_PAGES = 12;
        let calls = 0;
        let failMsg = null;
        const rawFut = [], rawSpot = [];
        // #2251 per-market ASK record. `spotRows: 0` alone cannot tell a
        // market the user never traded from a window that was never asked
        // for — and the field log showed exactly that ambiguity. Count the
        // windows and pages each market actually consumed, plus the first
        // window's start, so the answer is readable from one diag line.
        _dgBgAsk = { spot: { w: 0, p: 0, f0: 0 }, futures: { w: 0, p: 0, f0: 0 } };
        for (const mk of ['futures', 'spot']) {
          const sink = mk === 'spot' ? rawSpot : rawFut;
          let w0 = Math.max(0, Math.floor(bfFrm(mk, mk)));
          let span = BG_BF_SPAN_MS;
          _dgBgAsk[mk].f0 = w0;
          while (w0 < now) {
            _dgBgAsk[mk].w++;
            const left = BG_BF_CALL_CAP - calls;
            if (left <= 0) {
              gap = true; covOk = false;
              notes.push(mk + ' fill call cap reached — history is incomplete');
              break;
            }
            const w1 = Math.min(now, w0 + span);
            if (calls) await new Promise((rs) => setTimeout(rs, HB_PAGE_GAP_MS));
            const wk = await bgFillsWalk(creds, mk, w0, w1 + 1, route,
                                         Math.min(BG_BF_CHUNK_PAGES, left), HB_PAGE_GAP_MS);
            calls += wk.pages | 0;
            _dgBgAsk[mk].p += wk.pages | 0;
            if (!wk.ok) { failMsg = wk.message || ('Bitget ' + mk + ' fills fetch failed'); break; }
            for (const f of wk.rows) sink.push(f);
            if (wk.full) {
              // chunk overflowed the page cap — halve it until it fits
              // (already-fetched rows re-normalize; the merge dedups them)
              if (w1 - w0 <= 3600 * 1000) {
                gap = true; covOk = false;
                notes.push(mk + ' fills denser than the page cap in one hour — history is incomplete');
                w0 = w1 + 1;
              } else span = Math.max(3600 * 1000, Math.floor((w1 - w0) / 2));
              continue;
            }
            w0 = w1 + 1;
          }
          if (failMsg) break;
        }
        if (failMsg) {
          sc.bf = { ts: now, ok: false, msg: failMsg };
          lbSaveSoon();
          tdiag('lblot', 'backfill', { k: slot, v: venue, ok: 0, ms: Date.now() - now, err: String(failMsg) });
          return { ok: false, message: failMsg };
        }
        const fills = [];
        // Market comes from the ENDPOINT, never from the row: a Bitget spot
        // and a mix fill row are shape-identical.
        for (const f of rawFut) { const n = lbNormBitgetFill(f, 'futures'); if (n) fills.push(n); }
        for (const f of rawSpot) { const n = lbNormBitgetFill(f, 'spot'); if (n) fills.push(n); }
        _dgFutRows = rawFut.length;
        _dgSpotRows = rawSpot.length;
        _dgFetched = fills.length;
        added = lbScopeMerge(sc, fills);
      } else if (venue === 'kucoin') {
        // #2272: account-wide currentPage walks over BOTH hosts' /api/v1/fills
        // (engine KucoinHistory._fills_walk twin). There is no symbol universe
        // to resolve — coverage hinges purely on the call/page caps, so ANY cap
        // hit or overflowing page reports covOk:false and the panel keeps the
        // server blotter instead of activating on a partial history. PER-MARKET
        // windows: spot and futures are two hosts with two clocks, so one
        // shared high-water mark would truncate a window it never produced.
        const KC_BF_SPAN_MS = 7 * 86400 * 1000 - 60000;
        const KC_BF_CALL_CAP = 60;
        const KC_BF_CHUNK_PAGES = 12;
        let calls = 0;
        let failMsg = null;
        const rawFut = [], rawSpot = [];
        for (const mk of ['futures', 'spot']) {
          const sink = mk === 'spot' ? rawSpot : rawFut;
          let w0 = Math.max(0, Math.floor(bfFrm(mk, mk)));
          let span = KC_BF_SPAN_MS;
          while (w0 < now) {
            const left = KC_BF_CALL_CAP - calls;
            if (left <= 0) {
              gap = true; covOk = false;
              notes.push(mk + ' fill call cap reached — history is incomplete');
              break;
            }
            const w1 = Math.min(now, w0 + span);
            if (calls) await new Promise((rs) => setTimeout(rs, HB_PAGE_GAP_MS));
            const wk = await kcFillsWalk(creds, mk, w0, w1 + 1, route,
                                         Math.min(KC_BF_CHUNK_PAGES, left), HB_PAGE_GAP_MS);
            calls += wk.pages | 0;
            if (!wk.ok) { failMsg = wk.message || ('KuCoin ' + mk + ' fills fetch failed'); break; }
            for (const f of wk.rows) sink.push(f);
            if (wk.full) {
              if (w1 - w0 <= 3600 * 1000) {
                gap = true; covOk = false;
                notes.push(mk + ' fills denser than the page cap in one hour — history is incomplete');
                w0 = w1 + 1;
              } else span = Math.max(3600 * 1000, Math.floor((w1 - w0) / 2));
              continue;
            }
            w0 = w1 + 1;
          }
          if (failMsg) break;
        }
        if (failMsg) {
          sc.bf = { ts: now, ok: false, msg: failMsg };
          lbSaveSoon();
          tdiag('lblot', 'backfill', { k: slot, v: venue, ok: 0, ms: Date.now() - now, err: String(failMsg) });
          return { ok: false, message: failMsg };
        }
        // Futures sizes are integer CONTRACTS — resolve every symbol's
        // multiplier before normalizing. A symbol whose spec will not load is
        // a coverage HOLE, not a row to guess at: storing contracts as coins
        // would replay a 100× position on a 0.01-multiplier symbol.
        const kcm = {};
        for (const f of rawFut) {
          const s = String((f && f.symbol) || '');
          if (!s || kcm[s] !== undefined) continue;
          kcm[s] = await kcMult(s, route).catch(() => null);
        }
        const fills = [];
        // Market comes from the HOST, never from the row: a KuCoin spot and
        // futures fill row are shape-identical.
        const kcMiss = {};
        for (const f of rawFut) {
          const s = String((f && f.symbol) || '');
          const n = Number(kcm[s]) > 0 ? lbNormKucoinFill(f, 'futures', kcm[s]) : null;
          if (n) fills.push(n); else if (s) kcMiss[s] = 1;
        }
        for (const f of rawSpot) { const n = lbNormKucoinFill(f, 'spot', null); if (n) fills.push(n); }
        const missN = Object.keys(kcMiss);
        if (missN.length) {
          gap = true; covOk = false;
          notes.push('contract spec unavailable for ' + missN.slice(0, 4).join(', ')
                     + (missN.length > 4 ? ' +' + (missN.length - 4) + ' more' : '')
                     + ' — their fills could not be sized');
        }
        _dgFutRows = rawFut.length;
        _dgSpotRows = rawSpot.length;
        _dgFetched = fills.length;
        added = lbScopeMerge(sc, fills);
      } else {
        const futFrm = bfFrm('futures', 'futures');
        // spot watermarks: max numeric exec id per locally-known spot symbol
        const spotFrom = {};
        const symSet = {};
        for (const f of sc.rows) {
          if (f.market !== 'spot') continue;
          symSet[f.symbol] = 1;
          const eid = Math.floor(Number(f.exec_id) || 0);
          if (eid > (spotFrom[f.symbol] || 0)) spotFrom[f.symbol] = eid;
        }
        const extra = Array.isArray(intent.spotSymbols) ? intent.spotSymbols : [];
        for (const s of extra) if (s) symSet[String(s).toUpperCase()] = 1;
        const bnReq = (mkt, reqPath, params) => {
          if (mkt === 'spotPub') {
            // unsigned public GET, big cap (spot exchangeInfo is multi-MB;
            // #1977: unfiltered it crossed 16MB — request is shrunk at the
            // caller via showPermissionSets=false, 64MB cap is headroom)
            return httpJson(bnHost('spot'), 'GET', reqPath, formEnc(params || []),
                            null, {}, route, 64 * 1024 * 1024)
              .then((r) => {
                // #1977: a body clipped at the cap must fail HONESTLY as
                // coverage-unknown — never parse into a partial universe.
                if (r.tr) return { ok: false, message: 'Binance response truncated at byte cap' };
                let d = null;
                try { d = JSON.parse(r.text); } catch (e) { d = null; }
                return (r.status < 400 && d) ? { ok: true, data: d }
                  : { ok: false, message: 'Binance returned HTTP ' + r.status };
              })
              .catch((e) => transportFail(e, 'Binance'));
          }
          // #1975 signed backfill GETs (futures userTrades, spot myTrades,
          // spot account/openOrders) need a big response cap too — a full
          // 1000-row userTrades page can exceed the 256 KB httpJson default,
          // which truncates the body and JSON.parse fails ("unreadable
          // response"). Trading-path requests keep the default cap.
          return bnRequest(creds, 'GET', mkt, reqPath, params, route, 16 * 1024 * 1024);
        };
        // spot symbol UNIVERSE (holdings × quotes + open orders + local rows):
        // unknown universe = coverage unknown → covOk:false, panel keeps the
        // server blotter for this slot (best-effort fetch still runs).
        const uni = await lbBnSpotUniverse(bnReq, Object.keys(symSet));
        let spotList = Object.keys(symSet);
        if (uni.ok) spotList = uni.syms;
        else { covOk = false; gap = true; notes.push('spot coverage unknown — ' + (uni.message || 'account read failed')); }
        const r = await lbBnBackfill(bnReq, futFrm, now, spotList, spotFrom, HB_PAGE_GAP_MS);
        if (!r.ok) {
          sc.bf = { ts: now, ok: false, msg: r.message || 'backfill failed' };
          lbSaveSoon();
          tdiag('lblot', 'backfill', { k: slot, v: venue, ok: 0, ms: Date.now() - now,
            err: String(r.message || 'backfill failed') });   // #1973
          return { ok: false, message: r.message || 'backfill failed' };
        }
        if (r.gap) gap = true;
        if (r.covOk === false) covOk = false;
        for (const n of r.notes) notes.push(n);
        _dgFetched = (r.fills || []).length;   // #1973
        added = lbScopeMerge(sc, r.fills);
      }
      if (sc.rows.length > LB_ROWS_CAP) lbPruneTap(slot, venue, sc);
      sc.bf = { ts: now, ok: true, added: added, gap: gap, covOk: covOk,
                note: notes.join('; ') };
      const saved = await lbSaveNow();
      // #1973 field-test diag: hwm anchors, fetched vs merged (rest deduped),
      // duration + the explicit gap/coverage verdict and any horizon notes
      tdiag('lblot', 'backfill', { k: slot, v: venue, ok: 1, ms: Date.now() - now,
        hwmSpot: _dgHwmS, hwmFut: _dgHwmF, fetched: _dgFetched,
        futRows: _dgFutRows, spotRows: _dgSpotRows, merged: added,
        ask: _dgBgAsk ? ('sp ' + _dgBgAsk.spot.w + 'w/' + _dgBgAsk.spot.p + 'p@'
              + _dgBgAsk.spot.f0 + ' fu ' + _dgBgAsk.futures.w + 'w/'
              + _dgBgAsk.futures.p + 'p@' + _dgBgAsk.futures.f0) : undefined,
        dedup: _dgFetched - added, gap: gap ? 1 : 0, covOk: covOk ? 1 : 0,
        note: notes.join('; ') || undefined, total: sc.rows.length,
        persistErr: saved ? undefined : 1 });
      return { ok: true, added: added, gap: gap, covOk: covOk, to: now,
               note: notes.join('; '), count: sc.rows.length,
               ...(saved ? {} : { persistErr: true }) };
    } finally { delete _lbBfBusy[slot]; }
  }
  // #2112 device-source exchange RE-IMPORT into the LOCAL blotter store:
  // page the venue's own-trade REST/info over an explicit [frm,to] window
  // with the DEVICE key (HL: master address — no key material leaves the
  // device) and merge the normalized rows into the scope store as VENUE
  // TRUTH — in-window tombstones yield (lbReimportMerge, the sanctioned
  // window-scoped bypass), so previously pruned/quarantine-hidden fills are
  // re-accepted and the #2038 quarantine markers clear once the missing
  // prefix is back. Same normalizers + exec-id space as the live drain
  // lanes → a second run dedupes to added:0. The server/engine archive is
  // NOT touched here (the panel keeps its own engine POST leg where that
  // copy exists — engine stays the sole server archive writer). Page-cap
  // exhaustion FAILS visibly (narrow the window) — a truncated fetch must
  // never masquerade as complete venue truth; the merge itself is additive,
  // so a failed run never removes rows.
  const LB_RI_HL_PAGE_CAP = 12;
  const LB_RI_BYB_PAGE_CAP = 80;
  // (binance spot span cap LB_RI_BN_SPOT_WIN_MS is module-level — the #2160
  // precheck shares it with the walk so the two can never drift.)
  let _lbRiBusy = {};
  async function execLblotReimport(intent) {
    const venue = String(intent.venue || '');
    if (!lbVenueOk(venue)) return { ok: false, message: 'local blotter not supported for this venue' };
    const slot = String(intent.credSlot || venue);
    if (_lbRiBusy[slot]) return { ok: false, message: 're-import already in flight', busy: true };
    _lbRiBusy[slot] = true;
    const t0run = Date.now();
    // every failure leaves a c:"lblot" e:"reimp" tap — a device re-import
    // that restored nothing must be visible in field logs, never silent.
    const riFail = (msg) => {
      tdiag('lblot', 'reimp', { k: slot, v: venue, ok: 0, ms: Date.now() - t0run,
        err: String(msg || 'failed').slice(0, 300) });
      return { ok: false, message: msg };
    };
    try {
      const creds = credsGet(slot);
      if (!creds) return riFail('No API key on this device — provision Native trading first');
      const w = hbWindow(intent);
      if (!w) return riFail('Bad window (max 92 days)');
      const route = routeNorm(intent.route);
      const market = String(intent.market || 'both');
      const sleep = (ms) => new Promise((rs) => setTimeout(rs, ms));
      let gap = false;
      const notes = [];
      const fills = [];
      // #2167 gate-only: RAW per-leg row counts (pre-normalize) for the
      // reimp diag line — see the backfill twin's rationale.
      let riFutRows, riSpotRows;
      let hb = null;   // kraken: raw WS-shaped rows for the panel's engine POST leg
      if (venue === 'kraken') {
        // same walk as the #1844 desktop re-import source (TradesHistory +
        // /api/history futures fills; fails on page-cap exhaustion inside).
        const r = await lbKrBackfillRetry(hbKraken,
          { credSlot: slot, route: intent.route, market: market, frm: w.frm, to: w.to },
          sleep,
          (attempt, waitMs) => tdiag('lblot', 'reimp', { k: slot, v: venue,
            act: 'kr_budget_defer', attempt: attempt, waitMs: waitMs }),
          krResvFor(slot));   // #2168: reservation spans attempts + sleeps
        if (!r.ok) return riFail(r.message || 'kraken history fetch failed');
        if (r.bfTries > 1) notes.push('kraken rate budget deferred — ' + r.bfTries + ' attempts');
        for (const e of (r.spot || [])) { const f = lbNormKrWsSpot(e); if (f) fills.push(f); }
        for (const e of (r.futures || [])) { const f = lbNormKrWsFut(e); if (f) fills.push(f); }
        hb = { spot: r.spot || [], futures: r.futures || [] };
      } else if (venue === 'hyperliquid') {
        // account-level userFillsByTime pager (spot + main-dex + HIP-3 ride
        // one stream) by the MASTER address; rides the hlInfo budgeter.
        let addr;
        try { addr = await hlMasterResolve(String(creds.key).trim(), route); }
        catch (e) { return riFail('Hyperliquid master resolve failed: ' + ((e && e.message) || 'error')); }
        const wmErr = await hlEnsureProducts(route);
        if (wmErr) notes.push('spot symbol map unavailable — spot fills keep wire names');
        const raw = [];
        const seen = {};   // exec-id dedupe for boundary-ms overlap pages
        let cur = Math.max(0, Math.floor(w.frm));
        let pages = 0;
        for (;;) {
          const rp = await hlInfo({ type: 'userFillsByTime', user: addr,
                                    startTime: cur, endTime: w.to,
                                    aggregateByTime: false }, route);
          if (!rp.ok) return riFail(rp.message || 'Hyperliquid fills fetch failed');
          const rows = Array.isArray(rp.data) ? rp.data : [];
          const stp = lbHlPageStep(rows, cur, seen, raw);
          pages++;
          if (stp.gap) {
            // full page stuck on one ms — time paging cannot prove progress;
            // honest possible-gap note (merge stays additive → safe).
            gap = true;
            notes.push('fill page stalled on one timestamp — a gap is possible');
          }
          if (stp.done) break;
          cur = stp.next;
          if (pages >= LB_RI_HL_PAGE_CAP) return riFail('Window too large — fill history exceeds the page cap; narrow the date range');
        }
        const wm = hlProds.wireMap || {};
        for (const f of raw) { const n = lbNormHlFill(f, wm); if (n) fills.push(n); }
      } else if (venue === 'bybit') {
        // V5 /v5/execution/list: ≤7d query spans — chain windows over
        // [frm,to], cursor pages inside each chunk, per requested market.
        const BYB_RI_SPAN_MS = 7 * 86400 * 1000 - 60000;
        let pages = 0;
        const raw = [];
        const cats = market === 'spot' ? ['spot']
          : market === 'futures' ? ['linear'] : ['linear', 'spot'];
        for (const cat of cats) {
          let w0 = Math.max(0, Math.floor(w.frm));
          while (w0 < w.to) {
            const w1 = Math.min(w.to, w0 + BYB_RI_SPAN_MS);
            let cursor = '';
            for (;;) {
              if (pages >= LB_RI_BYB_PAGE_CAP) return riFail('Window too large — fill history exceeds the page cap; narrow the date range');
              const params = [['category', cat], ['startTime', String(w0)],
                              ['endTime', String(w1)], ['limit', '100']];
              if (cursor) params.push(['cursor', cursor]);
              if (pages) await sleep(HB_PAGE_GAP_MS);
              const rp = await bybRequest(creds, 'GET', '/v5/execution/list',
                                          params, null, route);
              pages++;
              if (!rp.ok) return riFail(rp.message || 'Bybit fills fetch failed');
              const res = ((rp.data || {}).result) || {};
              for (const f of res.list || []) {
                if (f && !f.category) f.category = cat;   // REST rows may omit it
                raw.push(f);
              }
              cursor = String(res.nextPageCursor || '');
              if (!cursor || !(res.list || []).length) break;
            }
            w0 = w1;
          }
        }
        for (const f of raw) { const n = lbNormBybFill(f); if (n) fills.push(n); }
      } else if (venue === 'gate') {
        // #2153: same walks as the gate backfill, over the explicit window.
        // Venue-truth contract: a truncated or unsizable fetch fails VISIBLY
        // (riFail), never a silent partial import.
        const GATE_RI_PAGE_CAP = 80;
        let pages = 0;
        const rawFut = [];
        const rawSpot = [];
        if (market !== 'spot') {
          let off = 0;
          for (;;) {
            if (pages >= GATE_RI_PAGE_CAP) return riFail('Window too large — fill history exceeds the page cap; narrow the date range');
            if (pages) await sleep(HB_PAGE_GAP_MS);
            const rp = await gateRequest(creds, 'GET', '/futures/usdt/my_trades_timerange',
              [['from', String(Math.floor(w.frm / 1000))], ['to', String(Math.ceil(w.to / 1000))],
               ['limit', '100'], ['offset', String(off)]], null, route);
            pages++;
            if (!rp.ok) {
              // spot-only key: no futures account is a normal state
              if (String(rp.message || '').indexOf('futures account') >= 0) break;
              return riFail(rp.message || 'Gate futures fills fetch failed');
            }
            const rows = Array.isArray(rp.data) ? rp.data : [];
            for (const f of rows) rawFut.push(f);
            if (rows.length < 100) break;
            off += rows.length;
          }
        }
        if (market !== 'futures') {
          const GATE_SPOT_SPAN_MAX = 29 * 86400 * 1000;
          let w0 = Math.max(0, Math.floor(w.frm));
          let span = GATE_SPOT_SPAN_MAX;
          while (w0 < w.to) {
            if (pages >= GATE_RI_PAGE_CAP) return riFail('Window too large — fill history exceeds the page cap; narrow the date range');
            const w1 = Math.min(w.to, w0 + span);
            let full2 = false;
            for (let pg = 1; pg <= 2; pg++) {
              if (pages) await sleep(HB_PAGE_GAP_MS);
              const rp = await gateRequest(creds, 'GET', '/spot/my_trades',
                [['from', String(Math.floor(w0 / 1000))], ['to', String(Math.ceil(w1 / 1000))],
                 ['limit', '1000'], ['page', String(pg)]], null, route);
              pages++;
              if (!rp.ok) return riFail(rp.message || 'Gate spot fills fetch failed');
              const rows = Array.isArray(rp.data) ? rp.data : [];
              for (const f of rows) rawSpot.push(f);
              if (rows.length < 1000) break;
              if (pg === 2) full2 = true;
            }
            if (full2) {
              if (w1 - w0 <= 3600 * 1000) return riFail('Spot fills denser than the page cap in one hour — narrow the date range');
              span = Math.max(3600 * 1000, Math.floor((w1 - w0) / 2));
              continue;
            }
            w0 = w1 + 1;
          }
        }
        const mset = {};
        for (const f of rawFut) { const cs = String((f && f.contract) || ''); if (cs) mset[cs] = 1; }
        for (const cs of Object.keys(mset)) { try { await gateMult(cs, route); } catch (e) { /* checked below */ } }
        for (const f of rawFut) {
          const cs = String((f && f.contract) || '');
          const mc = gateMultCache[cs];
          const n = lbNormGateFill(f, 'futures', mc ? mc.v : null);
          if (n) fills.push(n);
          else if (cs && !(mc && Number(mc.v) > 0)) {
            return riFail('Gate contract spec unavailable for ' + cs + ' — cannot size its fills; retry shortly');
          }
        }
        riFutRows = rawFut.length;
        riSpotRows = rawSpot.length;
        for (const f of rawSpot) { const n = lbNormGateFill(f, 'spot', null); if (n) fills.push(n); }
      } else if (venue === 'bitget') {
        // #2246: the backfill's walks over the EXPLICIT window. Venue-truth
        // contract — a truncated fetch of ANY kind fails VISIBLY (riFail),
        // never a short history reported as success.
        const BG_RI_SPAN_MS = 7 * 86400 * 1000 - 60000;
        const BG_RI_CALL_CAP = 80;
        const BG_RI_CHUNK_PAGES = 12;
        let calls = 0;
        const rawFut = [], rawSpot = [];
        const mks = market === 'spot' ? ['spot']
          : market === 'futures' ? ['futures'] : ['futures', 'spot'];
        for (const mk of mks) {
          const sink = mk === 'spot' ? rawSpot : rawFut;
          let w0 = Math.max(0, Math.floor(w.frm));
          let span = BG_RI_SPAN_MS;
          while (w0 < w.to) {
            const left = BG_RI_CALL_CAP - calls;
            if (left <= 0) return riFail('Window too large — fill history exceeds the page cap; narrow the date range');
            const w1 = Math.min(w.to, w0 + span);
            if (calls) await sleep(HB_PAGE_GAP_MS);
            const wk = await bgFillsWalk(creds, mk, w0, w1 + 1, route,
                                         Math.min(BG_RI_CHUNK_PAGES, left), HB_PAGE_GAP_MS);
            calls += wk.pages | 0;
            if (!wk.ok) return riFail(wk.message || ('Bitget ' + mk + ' fills fetch failed'));
            for (const f of wk.rows) sink.push(f);
            if (wk.full) {
              if (w1 - w0 <= 3600 * 1000) {
                return riFail('Bitget ' + mk + ' fills denser than the page cap in one hour — narrow the date range');
              }
              span = Math.max(3600 * 1000, Math.floor((w1 - w0) / 2));
              continue;
            }
            w0 = w1 + 1;
          }
        }
        riFutRows = rawFut.length;
        riSpotRows = rawSpot.length;
        for (const f of rawFut) { const n = lbNormBitgetFill(f, 'futures'); if (n) fills.push(n); }
        for (const f of rawSpot) { const n = lbNormBitgetFill(f, 'spot'); if (n) fills.push(n); }
      } else if (venue === 'kucoin') {
        // #2272: the backfill's walks over the EXPLICIT window. Venue-truth
        // contract — a truncated fetch of ANY kind fails VISIBLY (riFail),
        // never a short history reported as success.
        const KC_RI_SPAN_MS = 7 * 86400 * 1000 - 60000;
        const KC_RI_CALL_CAP = 80;
        const KC_RI_CHUNK_PAGES = 12;
        let calls = 0;
        const rawFut = [], rawSpot = [];
        const mks = market === 'spot' ? ['spot']
          : market === 'futures' ? ['futures'] : ['futures', 'spot'];
        for (const mk of mks) {
          const sink = mk === 'spot' ? rawSpot : rawFut;
          let w0 = Math.max(0, Math.floor(w.frm));
          let span = KC_RI_SPAN_MS;
          while (w0 < w.to) {
            const left = KC_RI_CALL_CAP - calls;
            if (left <= 0) return riFail('Window too large — fill history exceeds the page cap; narrow the date range');
            const w1 = Math.min(w.to, w0 + span);
            if (calls) await sleep(HB_PAGE_GAP_MS);
            const wk = await kcFillsWalk(creds, mk, w0, w1 + 1, route,
                                         Math.min(KC_RI_CHUNK_PAGES, left), HB_PAGE_GAP_MS);
            calls += wk.pages | 0;
            if (!wk.ok) return riFail(wk.message || ('KuCoin ' + mk + ' fills fetch failed'));
            for (const f of wk.rows) sink.push(f);
            if (wk.full) {
              if (w1 - w0 <= 3600 * 1000) {
                return riFail('KuCoin ' + mk + ' fills denser than the page cap in one hour — narrow the date range');
              }
              span = Math.max(3600 * 1000, Math.floor((w1 - w0) / 2));
              continue;
            }
            w0 = w1 + 1;
          }
        }
        riFutRows = rawFut.length;
        riSpotRows = rawSpot.length;
        for (const f of rawFut) {
          const cs = String((f && f.symbol) || '');
          const mult = cs ? await kcMult(cs, route).catch(() => null) : null;
          const n = Number(mult) > 0 ? lbNormKucoinFill(f, 'futures', mult) : null;
          if (n) fills.push(n);
          else if (cs && !(Number(mult) > 0)) {
            return riFail('KuCoin contract spec unavailable for ' + cs + ' — cannot size its fills; retry shortly');
          }
        }
        for (const f of rawSpot) { const n = lbNormKucoinFill(f, 'spot', null); if (n) fills.push(n); }
      } else {
        // binance: shell-signed time-window paging (never a raw host request
        // — bnRequest rides the httpJson bnBan freeze latch). bnReq twin of
        // the #1969 backfill's (big caps for 1000-row pages / exchangeInfo).
        const bnReq = (mkt, reqPath, params) => {
          if (mkt === 'spotPub') {
            return httpJson(bnHost('spot'), 'GET', reqPath, formEnc(params || []),
                            null, {}, route, 64 * 1024 * 1024)
              .then((r) => {
                if (r.tr) return { ok: false, message: 'Binance response truncated at byte cap' };
                let d = null;
                try { d = JSON.parse(r.text); } catch (e) { d = null; }
                return (r.status < 400 && d) ? { ok: true, data: d }
                  : { ok: false, message: 'Binance returned HTTP ' + r.status };
              })
              .catch((e) => transportFail(e, 'Binance'));
          }
          return bnRequest(creds, 'GET', mkt, reqPath, params, route, 16 * 1024 * 1024);
        };
        let calls = 0;
        // #2160 precheck BEFORE any trade fetch: enumerate the spot pair
        // universe first (the same source the walk uses — a few cheap
        // account/exchangeInfo reads, no trade paging) and reject when the
        // minimum call count for this window is already over budget.
        let bnSyms = [];
        if (market !== 'futures') {
          const symSet = {};
          for (const f of lbScope(slot).rows) {
            if (f.market === 'spot' && f.symbol) symSet[String(f.symbol).toUpperCase()] = 1;
          }
          for (const s of (Array.isArray(intent.spotSymbols) ? intent.spotSymbols : [])) {
            if (s) symSet[String(s).toUpperCase()] = 1;
          }
          const uni = await lbBnSpotUniverse(bnReq, Object.keys(symSet));
          if (!uni.ok) return riFail('Binance spot universe: ' + (uni.message || 'account read failed'));
          bnSyms = uni.syms.filter((s) => /^[A-Za-z0-9]{1,32}$/.test(String(s)));
          if (bnSyms.length > LB_BN_SPOT_SYM_CAP) return riFail('Too many spot pairs (' + bnSyms.length + ') — re-import futures and spot separately or reduce holdings pairs');
        }
        const pcRi = lbBnRiPrecheck(market, w.frm, w.to, bnSyms.length);
        if (pcRi) return riFail(pcRi.msg);
        if (market !== 'spot') {
          // futures userTrades: ≤7d spans, full page continues inside the
          // same window from the last ts (dedupe absorbs the overlap).
          let t0 = Math.max(0, Math.floor(w.frm));
          while (t0 < w.to) {
            if (++calls > LB_BN_MAX_CALLS) return riFail('Window too large — fill history exceeds the call cap; narrow the date range');
            const t1 = Math.min(t0 + LB_BN_FUT_WIN_MS, w.to);
            if (calls > 1) await sleep(HB_PAGE_GAP_MS);
            const r = await bnReq('futures', '/fapi/v1/userTrades',
              [['startTime', String(t0)], ['endTime', String(t1)], ['limit', '1000']]);
            if (!r || !r.ok) return riFail('Binance futures: ' + ((r && r.message) || 'request failed'));
            const rows = Array.isArray(r.data) ? r.data : [];
            let lastTs = 0;
            for (const raw of rows) {
              const f = lbNormBnFutRest(raw);
              if (f) { fills.push(f); if (f.ts > lastTs) lastTs = f.ts; }
            }
            const stp = lbBnWinStep(rows.length, lastTs, t0, t1, 1000);
            if (stp.stuck) return riFail('Binance futures: a full trades page could not advance past one timestamp — history too dense for time paging in this window');
            t0 = stp.next;
          }
        }
        if (market !== 'futures') {
          // spot myTrades: per-symbol, ≤24h spans. Universe = held assets ×
          // quotes + open orders + locally known symbols (Binance has no
          // account-wide spot trades endpoint) — enumerated up front by the
          // #2160 precheck above; an unknown universe is an honest failure,
          // never a silently partial restore.
          for (const sym of bnSyms) {
            let t0 = Math.max(0, Math.floor(w.frm));
            while (t0 < w.to) {
              if (++calls > LB_BN_MAX_CALLS) return riFail('Window too large for the pair count — narrow the date range');
              const t1 = Math.min(t0 + LB_RI_BN_SPOT_WIN_MS, w.to);
              if (calls > 1) await sleep(HB_PAGE_GAP_MS);
              const r = await bnReq('spot', '/api/v3/myTrades',
                [['symbol', sym], ['startTime', String(t0)], ['endTime', String(t1)], ['limit', '1000']]);
              if (!r || !r.ok) return riFail('Binance spot (' + sym + '): ' + ((r && r.message) || 'request failed'));
              const rows = Array.isArray(r.data) ? r.data : [];
              let lastTs = 0;
              for (const raw of rows) {
                const f = lbNormBnSpotRest(raw);
                if (f) { fills.push(f); if (f.ts > lastTs) lastTs = f.ts; }
              }
              const stp = lbBnWinStep(rows.length, lastTs, t0, t1, 1000);
              if (stp.stuck) return riFail('Binance spot (' + sym + '): a full trades page could not advance past one timestamp — history too dense for time paging in this window');
              t0 = stp.next;
            }
          }
        }
      }
      // requested-market scope (kraken/HL walks are venue/account-wide)
      const use = market === 'both' ? fills
        : fills.filter((f) => String(f.market || '') === market);
      // live-cache drain first so the quarantine before/after diff and the
      // merge both see the full current store.
      lbDrain(slot, venue);
      const sc = lbScope(slot);
      const slotAid = (() => {
        const m = /#a(\d+)$/.exec(slot);
        return m ? parseInt(m[1], 10) : 0;
      })();
      if (slotAid) for (const f of use) f.aid = slotAid;
      const quarBefore = lbSpotQuar(sc.rows).quar.length;
      const m = lbReimportMerge(sc, use, w.frm, w.to);
      if (sc.rows.length > LB_ROWS_CAP) lbPruneTap(slot, venue, sc);
      const quarAfter = lbSpotQuar(sc.rows).quar.length;
      const quarCleared = Math.max(0, quarBefore - quarAfter);
      if (quarCleared) _lbQuarSig[slot] = '';   // re-arm the quar tap dedupe
      // #2234: a re-import replaces rows in place and clears tombstones — the
      // replay cache's group signatures and the drain's ring cursors both have
      // to start over (a cleared tombstone makes ring rows mergeable again).
      lbStoreMut(slot, sc);
      const saved = await lbSaveNow();
      tdiag('lblot', 'reimp', { k: slot, v: venue, ok: 1, mkt: market,
        frm: w.frm, to: w.to, ms: Date.now() - t0run, fetched: use.length,
        futRows: riFutRows, spotRows: riSpotRows,
        n: m.added, dedup: m.skipped, tomb: m.tombCleared,
        quarCleared: quarCleared, gap: gap ? 1 : 0,
        note: notes.join('; ') || undefined, total: sc.rows.length,
        persistErr: saved ? undefined : 1 });
      return { ok: true, added: m.added, skipped: m.skipped,
               tombCleared: m.tombCleared, quarCleared: quarCleared,
               count: sc.rows.length, gap: gap, note: notes.join('; '),
               ...(hb ? { hb: hb } : {}),
               ...(saved ? {} : { persistErr: true }) };
    } finally { delete _lbRiBusy[slot]; }
  }

  async function execIntent(intent) {
    // Read-only latency probe (op:'ping_rt') — handled BEFORE validation and
    // creds: no keys, no signing, no order. One cheap public GET/POST against
    // the venue's REST host via the SAME route arg orders would ride, so the
    // panel's Order/Exec chips show the honest native round-trip and the IPC
    // handler's via-echo confirms the "Trading: Native·…" label. Old shells
    // without this branch fall through to validateIntent's 'unknown op' — the
    // panel treats that as unsupported and stamps nothing.
    if (intent && typeof intent === 'object' && intent.op === 'acct_read') return await execAcctRead(intent);
    // Phemex native fills read (Your-trades archive source on device-key-only
    // setups) — creds-signed but read-only; venue-gated (Phemex-first pattern).
    if (intent && typeof intent === 'object' && intent.op === 'fills_read') {
      if (intent.venue === 'phemex') return await execPhemexFillsRead(intent);
      if (intent.venue === 'kraken') return await execKrakenFillsRead(intent);   // #1814 WS-cache read
      return { ok: false, message: 'fills_read not supported for this venue' };
    }
    // #1820 one-shot REST fills seed (kraken) — rate-limited inside; old
    // shells fall through to 'unknown op' and the panel treats it as a no-op.
    if (intent && typeof intent === 'object' && intent.op === 'fills_seed') {
      if (intent.venue === 'kraken') return await execKrakenFillsSeed(intent);
      return { ok: false, message: 'fills_seed not supported for this venue' };
    }
    // #1966 Kraken futures leverage GET/PUT (device-signed — see
    // execKrakenLeverage). Old shells fall through to 'unknown op' and the
    // panel falls back to the server path (never a dead chip).
    if (intent && typeof intent === 'object' && intent.op === 'leverage') {
      if (intent.venue === 'kraken') return await execKrakenLeverage(intent);
      if (intent.venue === 'hyperliquid') return await execHlLeverage(intent);   // #2000
      if (intent.venue === 'bybit') return await execBybLeverage(intent);   // #2051
      if (intent.venue === 'gate') return await execGateLeverage(intent);   // #2153
      if (intent.venue === 'bitget') return await execBitgetLeverage(intent);   // #2247
      if (intent.venue === 'kucoin') return await execKucoinLeverage(intent);   // #2272
      return { ok: false, message: 'leverage not supported for this venue' };
    }
    // #1844 own-trade history backfill (re-import source) — kraken/phemex
    // raw rows for the panel to POST to /history/reimport. Old shells fall
    // through to 'unknown op'; the panel then offers the server-key path.
    if (intent && typeof intent === 'object' && intent.op === 'history_backfill') {
      return await execHistoryBackfill(intent);
    }
    // #1969 device-local blotter ops (kraken/binance): read/merge/delete the
    // persistent local fills store; backfill "since my newest local fill".
    if (intent && typeof intent === 'object' && intent.op === 'lblot_read') {
      return await execLblotRead(intent);
    }
    if (intent && typeof intent === 'object' && intent.op === 'lblot_trades') {
      return await execLblotTrades(intent);
    }
    if (intent && typeof intent === 'object' && intent.op === 'lblot_ingest') {
      return await execLblotIngest(intent);
    }
    if (intent && typeof intent === 'object' && intent.op === 'lblot_delete') {
      return await execLblotDelete(intent);
    }
    if (intent && typeof intent === 'object' && intent.op === 'lblot_backfill') {
      return await execLblotBackfill(intent);
    }
    // #2112 device-source exchange re-import → LOCAL store (venue truth,
    // in-window tombstone yield). Old shells fall through to 'unknown op';
    // the panel gates the picker option on the 'lblotri' cap.
    if (intent && typeof intent === 'object' && intent.op === 'lblot_reimport') {
      return await execLblotReimport(intent);
    }
    // PUBLIC catalog/kline bridge (#1713) — no creds, strict allowlist inside.
    // Generic PUBLIC catalog bridge (#1715) — allowlisted https GETs (+ HL POST /info) inside.
    if (intent && typeof intent === 'object' && intent.op === 'cat_http') return await execCatHttp(intent);
    if (intent && typeof intent === 'object' && intent.op === 'cat_fetch') return await execCatFetch(intent);
    // Opportunistic re-warm (op:'warm') — no keys, no signing, no order.
    // Fire-and-forget warm of every REST host the venue's orders can dial
    // (rate-limited per venue+host inside warmVenue); returns ok immediately.
    // Old shells fall through to 'unknown op' — the panel treats that as
    // unsupported and simply stops sending warms.
    if (intent && typeof intent === 'object' && intent.op === 'warm') {
      if (TRADE_VENUES.indexOf(intent.venue) < 0) return { ok: false, message: 'venue not supported natively' };
      warmVenue(intent.venue, routeNorm(intent.route));
      return { ok: true };
    }
    if (intent && typeof intent === 'object' && intent.op === 'ping_rt') {
      if (TRADE_VENUES.indexOf(intent.venue) < 0) return { ok: false, message: 'venue not supported natively' };
      const tgt = pingRtTarget(intent.venue, intent.market === 'spot' ? 'spot' : 'futures');
      if (!tgt) return { ok: false, message: 'no probe target for this venue' };
      const route = routeNorm(intent.route);
      try {
        const r = await httpJson(tgt.host, tgt.method, tgt.path, '', tgt.body, {}, route);
        // Any answer from the venue host < 500 counts — the probe measures the
        // path, not the endpoint's semantics.
        if (!r || !r.status || r.status >= 500) {
          return { ok: false, message: 'venue ping failed (HTTP ' + ((r && r.status) || 0) + ')' };
        }
        return { ok: true };
      } catch (e) {
        const em = (e && e.message) || 'error';
        if (em === 'proxy-unavailable') return { ok: false, message: 'Proxy is enabled but unavailable' };
        return { ok: false, message: 'venue ping failed: ' + em };
      }
    }
    const verr = validateIntent(intent);
    if (verr) return { ok: false, message: verr };
    // Per-account slot: aid>0 intents carry credSlot='venue#aN' and sign with
    // THAT slot's creds ONLY (no base-account fallback — fail closed).
    const creds = credsGet(intent.credSlot || intent.venue);
    if (!creds) return { ok: false, message: 'No API key on this device — provision Native trading first' };
    const route = routeNorm(intent.route);
    try {
      if (intent.venue === 'binance') return await execBinance(creds, intent, route);
      if (intent.venue === 'bybit') {
        const r = await execBybit(creds, intent, route);
        // #2051: a successful trade ack kicks the push lane awake (no-op
        // while the loop runs) and stamps an optimistic mutation so the
        // badge/posrow read fires immediately after the REST ack.
        if (r && r.ok) {
          try { bybPushEnsure(intent.credSlot || 'bybit', creds, route); }
          catch (e) { /* REST path */ }
          try {
            if (intent.op === 'cancel' && intent.orderID) {
              bybMutKick(intent.credSlot || 'bybit', 'ordgone', String(intent.orderID));
            } else bybMutKick(intent.credSlot || 'bybit', 'order');
          } catch (e) { /* diag-only */ }
        }
        return r;
      }
      if (intent.venue === 'okx') return await execOkx(creds, intent, route);
      if (intent.venue === 'gate') {
        const r = await execGate(creds, intent, route);
        // #2153: a successful trade ack kicks the push lane awake (no-op
        // while the loops run) and stamps an optimistic mutation so the
        // badge/posrow read fires immediately after the REST ack. Market-
        // scoped — gate order id spaces are per-market (spot vs futures).
        if (r && r.ok) {
          try { gatePushEnsure(intent.credSlot || 'gate', creds, route); }
          catch (e) { /* REST path */ }
          try {
            const gmk = intent.market === 'spot' ? 'spot' : 'futures';
            if (intent.op === 'cancel' && intent.orderID) {
              gateMutKick(intent.credSlot || 'gate', 'ordgone', String(intent.orderID), gmk);
            } else gateMutKick(intent.credSlot || 'gate', 'order', null, gmk);
          } catch (e) { /* diag-only */ }
        }
        return r;
      }
      if (intent.venue === 'bitget') {
        const r = await execBitget(creds, intent, route);
        // #2247: a successful trade ack kicks the push lane awake (no-op
        // while the loop runs) and stamps an optimistic mutation so the
        // badge/posrow read fires immediately after the REST ack. Market-
        // scoped — bitget order id spaces are per-market (spot vs futures).
        if (r && r.ok) {
          try { bgPushEnsure(intent.credSlot || 'bitget', creds, route); }
          catch (e) { /* REST path */ }
          try {
            const bmk = intent.market === 'spot' ? 'spot' : 'futures';
            if (intent.op === 'cancel' && intent.orderID) {
              bgMutKick(intent.credSlot || 'bitget', 'ordgone', String(intent.orderID), bmk);
            } else bgMutKick(intent.credSlot || 'bitget', 'order', null, bmk);
          } catch (e) { /* diag-only */ }
        }
        return r;
      }
      if (intent.venue === 'kucoin') {
        const r = await execKucoin(creds, intent, route);
        // #2272: a successful trade ack kicks the push lane awake (no-op
        // while the loops run) and stamps an optimistic mutation so the
        // badge/posrow read fires immediately after the REST ack. Market-
        // scoped — KuCoin order id spaces are per-market (two hosts). A
        // freshly placed STOP forwards its trigger direction so the chip
        // renders the right family at once (no wrong-colour flicker).
        if (r && r.ok) {
          try { kcPushEnsure(intent.credSlot || 'kucoin', creds, route); }
          catch (e) { /* REST path */ }
          try {
            const kmk = intent.market === 'spot' ? 'spot' : 'futures';
            if (intent.op === 'cancel' && intent.orderID) {
              kcMutKick(intent.credSlot || 'kucoin', 'ordgone', String(intent.orderID), kmk);
            } else kcMutKick(intent.credSlot || 'kucoin', 'order', null, kmk, r.kcStop || null);
          } catch (e) { /* diag-only */ }
        }
        return r;
      }
      if (intent.venue === 'bitmex') return await execBitmex(creds, intent, route);
      if (intent.venue === 'mexc') return await execMexc(creds, intent, route);
      if (intent.venue === 'hyperliquid') {
        const r = await execHyperliquid(creds, intent, route);
        // #2000: a successful trade ack kicks the HL push lane awake (no-op
        // while the loop runs) so the fill/order lands push-fast.
        if (r && r.ok) {
          try { hlPushEnsure(intent.credSlot || 'hyperliquid', creds, route); }
          catch (e) { /* REST path */ }
        }
        return r;
      }
      if (intent.venue === 'asterdex') return await execAster(creds, intent, route);
      if (intent.venue === 'arcus') return await execArcus(creds, intent, route);
      if (intent.venue === 'lighter') return await execLighter(creds, intent, route);
      if (intent.venue === 'kraken') {
        const r = await execKraken(creds, intent, route);
        // #1826: every successful trade ack busts the acct_read memo (all
        // ops here mutate — reads ride acct_read) + kicks the spot fast lane.
        if (r && r.ok) {
          krTradeAckKick(intent.credSlot || 'kraken', creds, route,
                         intent.market === 'spot' ? 'spot' : 'futures');
        } else if (r && intent.market === 'spot' &&
                   /insufficient funds/i.test(String(r.message || ''))) {
          // #1890: the venue rejecting a spot order for funds proves the
          // LOCAL balance view is wrong (an inflated qty prefilled sell-all)
          // — force ONE paced venue-truth confirm now instead of waiting on
          // the next successful ACK (which never comes while sells bounce).
          krTradeAckKick(intent.credSlot || 'kraken', creds, route, 'spot');
        }
        return r;
      }
      if (intent.op === 'close') {
        // Positions lookup → reduce-only market for the full size; ONE retry
        // on a miss (fresh-position REST lag), mirroring the engine.
        let pr = await fetchPositions(creds, route);
        if (!pr.ok) return pr;
        let pos = findPosition(pr.rows, intent.symbol);
        if (!pos) {
          pr = await fetchPositions(creds, route);
          if (!pr.ok) return pr;
          pos = findPosition(pr.rows, intent.symbol);
        }
        if (!pos) return { ok: false, message: 'Position not found' };
        const side = String(pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
        const body = phemexFuturesOrderBody(pos.symbol, side, 'market', pos.size,
                                            null, intent.clOrdID, { reduceOnly: true });
        const r = await phemexHedgeRecoveryFlow(
          (step) => signedRequest(creds, step, route),
          { method: 'POST', path: '/g-orders', query: '', body: body });
        if (!r.ok) return r;
        const oid = r.data && (r.data.orderID || r.data.orderId);
        return { ok: true, orderID: oid || null, clOrdID: intent.clOrdID };
      }
      if (intent.op === 'sltp') {
        let pr = await fetchPositions(creds, route);
        if (!pr.ok) return pr;
        let pos = findPosition(pr.rows, intent.symbol);
        if (!pos) {
          pr = await fetchPositions(creds, route);
          if (!pr.ok) return pr;
          pos = findPosition(pr.rows, intent.symbol);
        }
        if (!pos) return { ok: false, message: 'No open position to protect' };
        const terr = sltpTriggerOk(intent.kind, pos.side, intent.trigger, pos.mark);
        if (terr) return { ok: false, message: terr };
        const side = String(pos.side).toLowerCase() === 'buy' ? 'sell' : 'buy';
        const ordType = intent.kind === 'sl' ? 'stop' : 'tp_market';
        const body = phemexFuturesOrderBody(pos.symbol, side, ordType, pos.size,
                                            null, intent.clOrdID,
                                            { reduceOnly: true, trigger: intent.trigger,
                                              closeOnTrigger: true });
        const r = await phemexHedgeRecoveryFlow(
          (step) => signedRequest(creds, step, route),
          { method: 'POST', path: '/g-orders', query: '', body: body });
        if (!r.ok) return r;
        const oid = r.data && (r.data.orderID || r.data.orderId);
        return { ok: true, kind: intent.kind, orderID: oid || null, clOrdID: intent.clOrdID };
      }
      // order / cancel / cancel_all ride the pure request builders.
      let spec = null;
      if (intent.op === 'order' && intent.market === 'spot') {
        try { spec = await spotSpec(intent.symbol, route); }
        catch (e) {
          // Catalog fetch/parse failed — NOT a symbol problem. Honest error;
          // "Unknown spot symbol" is reserved for a loaded catalog miss.
          return { ok: false, message: "Couldn't load Phemex spot catalog — order NOT sent ("
                                       + ((e && e.message) || 'error') + ')' };
        }
        if (!spec) return { ok: false, message: 'Unknown spot symbol ' + intent.symbol };
      }
      let steps;
      try { steps = buildPhemexRequests(intent, spec); } catch (e) {
        return { ok: false, message: (e && e.message) || 'bad intent' };
      }
      let last = null;
      for (const step of steps) {
        // Futures order POSTs get the 20004 hedge-mode recovery (switch the
        // symbol to one-way + single retry); everything else is unchanged.
        last = (step.method === 'POST' && step.path === '/g-orders')
          ? await phemexHedgeRecoveryFlow((s) => signedRequest(creds, s, route), step)
          : await signedRequest(creds, step, route);
        if (!last.ok) return last;   // FAIL LOUD — no partial-success masking
      }
      if (intent.op === 'order') {
        const oid = last.data && (last.data.orderID || last.data.orderId);
        return { ok: true, orderID: oid || null, clOrdID: intent.clOrdID };
      }
      if (intent.op === 'cancel') return { ok: true, cancelled: intent.orderID };
      return { ok: true, cancelled: 'all' };
    } catch (e) {
      // Connect-phase failures reaching here already ATE their one automatic
      // retry (httpJson) — map the raw Node message to a friendlier one, but
      // never mask a real venue rejection (connectPhaseError is transport-only).
      if (connectPhaseError(e)) {
        return { ok: false, message: 'Connection to the venue dropped while connecting (already retried once) — check proxy/network and try again' };
      }
      return { ok: false, message: 'Native trade failed: ' + ((e && e.message) || 'error') };
    }
  }

  // First-action warmth: when trading is ARMED for a venue (creds set) — and
  // opportunistically on cheap user signals (op:'warm' from board open /
  // window focus) — fire ONE cheap unauthenticated GET/POST at EVERY REST
  // host the venue's orders can dial (split-host venues: kraken api. +
  // futures., mexc, binance, kucoin, asterdex) so the first real order
  // doesn't pay the SOCKS+TCP+TLS handshake. Where the warm target IS the
  // venue's time endpoint the GET rides ensureVenueTime(force) so it ALSO
  // pre-resolves the clock offset — the first signed request then stamps a
  // cached offset instead of round-tripping a time probe on a cold socket
  // (kraken spot's Cloudflare front made that doubly expensive). Rate-limited
  // per venue+host (WARM_MIN_GAP_MS); _kaWarmed is cleared by
  // flushKeepAliveAgents, so a proxy change re-warms on the next arm.
  // Fire-and-forget, silent on failure — NO timer loop.
  function warmVenue(venue, route) {
    try {
      const now = Date.now();
      for (const tgt of warmTargetsFor(venue)) {
        if (!rewarmDue(_kaWarmed.get(tgt.key), now)) continue;
        _kaWarmed.set(tgt.key, now);
        if (venueTimeProbeKey(venue, tgt.market)) {
          // Target is the venue time endpoint → warm + seed the offset cache.
          ensureVenueTime(venue, tgt.market, route, true)
            .catch(() => { /* best-effort; real action surfaces errors */ });
        } else {
          httpJson(tgt.host, tgt.method, tgt.path, '', tgt.body, {}, route)
            .catch(() => { /* warm-up is best-effort; real action will surface errors */ });
        }
      }
      // #1857: Kraken trade-connection pre-warm — the first order's real cold
      // cost is the private WS order-entry session (token dance + connect),
      // not just the REST socket. Kick krWsEnsure for every armed kraken slot
      // so the session loop is already live before the first click; the loop
      // self-maintains (reconnect/backoff), so this is a one-time kick per
      // slot — NO recurring token spend, and a no-op while the loop runs.
      if (venue === 'kraken') {
        try {
          const all = credsLoadAll();
          for (const k of Object.keys(all)) {
            const sn2 = tnSlotNorm(k);
            if (!sn2 || sn2.base !== 'kraken') continue;
            const c = credsGet(k);
            if (c) { try { krWsEnsure(k, c, route); } catch (e) { /* REST path */ } }
          }
        } catch (e) { /* non-fatal */ }
      }
      // #1943: same one-time kick for Binance user-data streams — the push
      // channel is live before the first order/read; loops self-maintain.
      if (venue === 'binance') {
        try {
          const all = credsLoadAll();
          for (const k of Object.keys(all)) {
            const sn2 = tnSlotNorm(k);
            if (!sn2 || sn2.base !== 'binance') continue;
            const c = credsGet(k);
            if (c) { try { bnUdsEnsure(k, c, route); } catch (e) { /* REST path */ } }
          }
        } catch (e) { /* non-fatal */ }
      }
      // #2000: same one-time kick for the Hyperliquid account push lane
      // (address-keyed info WS — userFills + orderUpdates); self-maintains.
      if (venue === 'hyperliquid') {
        try {
          const all = credsLoadAll();
          for (const k of Object.keys(all)) {
            const sn2 = tnSlotNorm(k);
            if (!sn2 || sn2.base !== 'hyperliquid') continue;
            const c = credsGet(k);
            if (c) { try { hlPushEnsure(k, c, route); } catch (e) { /* REST path */ } }
          }
        } catch (e) { /* non-fatal */ }
      }
      // #2153: same one-time kick for the Gate private push sockets (spot +
      // futures orders/usertrades/positions/balances); loops self-maintain.
      if (venue === 'gate') {
        try {
          const all = credsLoadAll();
          for (const k of Object.keys(all)) {
            const sn2 = tnSlotNorm(k);
            if (!sn2 || sn2.base !== 'gate') continue;
            const c = credsGet(k);
            if (c) { try { gatePushEnsure(k, c, route); } catch (e) { /* REST path */ } }
          }
        } catch (e) { /* non-fatal */ }
      }
      // #2247: same one-time kick for the Bitget private push socket (ONE
      // conn carrying both instTypes: orders/positions/account); loop
      // self-maintains.
      if (venue === 'bitget') {
        try {
          const all = credsLoadAll();
          for (const k of Object.keys(all)) {
            const sn2 = tnSlotNorm(k);
            if (!sn2 || sn2.base !== 'bitget') continue;
            const c = credsGet(k);
            if (c) { try { bgPushEnsure(k, c, route); } catch (e) { /* REST path */ } }
          }
        } catch (e) { /* non-fatal */ }
      }
      // #2272: same one-time kick for the KuCoin private push sockets (TWO
      // conns — spot and futures live on different hosts); loops self-maintain.
      if (venue === 'kucoin') {
        try {
          const all = credsLoadAll();
          for (const k of Object.keys(all)) {
            const sn2 = tnSlotNorm(k);
            if (!sn2 || sn2.base !== 'kucoin') continue;
            const c = credsGet(k);
            if (c) { try { kcPushEnsure(k, c, route); } catch (e) { /* REST path */ } }
          }
        } catch (e) { /* non-fatal */ }
      }
    } catch (e) { /* non-fatal */ }
  }

  // --- IPC surface -----------------------------------------------------------
  ipcMain.handle('att:trade-creds-set', (event, venue, creds) => {
    if (!senderOk(event)) return { ok: false, error: 'forbidden' };
    // Accepts 'venue' OR the multi-account 'venue#aN' slot (panel termVK);
    // creds store under the SLOT, warmth/hosts key the BASE venue (agents are
    // per venue — never duplicated per account slot).
    const sn = tnSlotNorm(venue);
    if (!sn) return { ok: false, error: 'bad-venue' };
    if (!creds || typeof creds !== 'object') return { ok: false, error: 'bad-creds' };
    const r = credsSet(sn.slot, creds);
    if (r && r.ok) warmVenue(sn.base);   // arm → pre-open one warm connection
    // Diag: the ARM event only — slot name, success. NEVER key material.
    tdiag('acct', 'arm', { slot: sn.slot, ok: !!(r && r.ok) });
    return r;
  });
  ipcMain.handle('att:trade-creds-wipe', (event, venue) => {
    if (!senderOk(event)) return { ok: false, error: 'forbidden' };
    const sn = tnSlotNorm(venue);
    if (!sn) return { ok: false, error: 'bad-venue' };
    return credsWipe(sn.slot);
  });
  ipcMain.handle('att:trade-creds-status', (event) => {
    if (!senderOk(event)) return { ok: false, error: 'forbidden' };
    return credsStatus();
  });
  // #2234 shared serialized account read. The guard's memo serves ONE object
  // to every window inside its window, so the JSON is built once per RESULT
  // (WeakMap-keyed on that object — no cache to invalidate, it dies with the
  // memo entry) and every window after the first pays only a string copy.
  // Unserializable result ⇒ the old object shape, never an error.
  const _arShareJson = new WeakMap();
  function acctReadShare(r) {
    if (!r || typeof r !== 'object') return r;
    let j = _arShareJson.get(r);
    if (j === undefined) {
      try { j = JSON.stringify(r); } catch (e) { j = null; }
      _arShareJson.set(r, j);
    }
    if (typeof j !== 'string') return r;
    return { ok: !!r.ok, json: j };
  }
  // Diag: array-field row counts of a read result (positions/orders/wallets/
  // fills lengths) — counts only, never row contents.
  function diagRowCounts(r) {
    const out = {};
    if (!r || typeof r !== 'object') return out;
    for (const k of Object.keys(r)) {
      if (Array.isArray(r[k])) out[k] = r[k].length;
      else if (r[k] && typeof r[k] === 'object') {
        for (const k2 of Object.keys(r[k])) {
          if (Array.isArray(r[k][k2])) out[k + '.' + k2] = r[k][k2].length;
        }
      }
    }
    return out;
  }

  ipcMain.handle('att:trade-exec', async (event, intent) => {
    if (!senderOk(event)) return { ok: false, message: 'forbidden' };
    const diagT0 = Date.now();
    const r = await execIntent(intent);
    // Echo the path this exec ACTUALLY used (agentFor is the same pick every
    // request in the intent rode) so the panel can label "Trading:
    // Native·Proxy/Direct" from CONFIRMED fact, never from the pref. A
    // refused agent (proxy on, unbuildable) echoes {refused:true}.
    if (r && typeof r === 'object' && !r.via) {
      try {
        r.via = tradeViaFromAgent(agentFor(intent && intent.route));
        // Socket-reuse marker (req.reusedSocket of the last completed HTTP
        // round-trip): lets the panel's ping-chip tooltip show whether the
        // warm keep-alive pool is really being hit on this route.
        if (_lastReused !== null) r.via.reused = _lastReused;
      }
      catch (e) { /* non-fatal — label just stays pending */ }
    }
    // #2131: every ACKed mutating op marks the venue HOT (one choke point for
    // ALL venues) so its follow-up account reads dispatch ahead of routine
    // idle-venue polls for ACCT_HOT_MS. Reorders only — budgets untouched.
    if (intent && typeof intent === 'object' && r && r.ok) {
      const mop = String(intent.op || '');
      if (mop === 'order' || mop === 'cancel' || mop === 'cancel_all' ||
          mop === 'close' || mop === 'close_pos' || mop === 'amend' ||
          mop === 'sltp') {
        try { execAcctRead.markHot(String(intent.venue || '')); } catch (e) { /* pre-init */ }
      }
    }
    // Diag summaries for the read + order layers (#1786), after the via stamp
    // (test pins slice the handler head). Orders log venue/market/symbol/side/
    // qty ONLY (design rule); reads log status, pacing and row counts.
    if (diagTap && intent && typeof intent === 'object') {
      const op = String(intent.op || '');
      if (op === 'acct_read' || op === 'fills_read') {
        const dd = { k: String(intent.venue || ''), venue: intent.venue,
                     market: intent.market, ok: !!(r && r.ok),
                     paced: !!(r && r.rateLimited), ms: Date.now() - diagT0,
                     rows: diagRowCounts(r && r.data ? r.data : r) };
        // #2131: queue wait vs HTTP time at a glance — prio + queued-wait ms
        // (stamped by the guard's dispatch gate; absent on memo/paced hits).
        // #2281: pool depth at dispatch + queued waiters — the saturation
        // gauge a capture needs to separate "the pool was full" from "the
        // venue was slow" without reconstructing it from overlapping spans.
        if (r && r.prio) {
          dd.prio = r.prio;
          if (Number.isFinite(r.qms)) dd.qms = r.qms;
          if (Number.isFinite(r.inf)) dd.inf = r.inf;
          if (Number.isFinite(r.qw)) dd.qw = r.qw;
        }
        tdiag('acct', op, dd);
      } else if (op === 'order' || op === 'cancel' || op === 'cancel_all' ||
                 op === 'close_pos' || op === 'amend') {
        const dd = { k: String(intent.venue || ''), venue: intent.venue,
                     market: intent.market, symbol: intent.symbol,
                     side: intent.side, qty: intent.qty,
                     ok: !!(r && r.ok), ms: Date.now() - diagT0 };
        // #1832 diag honesty: the venue error string (first error code) on
        // every failed trade — Kraken's EAPI:Rate limit rides an HTTP 200
        // body, so without this the log shows only healthy-looking s:200.
        if (!dd.ok && r && r.message) dd.err = String(r.message).slice(0, 120);
        tdiag('trade', op, dd);
      }
    }
    // #2234 per-window fan-out: the read memo hands the SAME result object to
    // every window, and each IPC reply structured-clones it — 334 KB / 1.4 ms
    // for a binance account with 865 positions, once per window per read. A
    // caller that opts in gets the object serialized ONCE and shared as a
    // string instead (~0.15 ms to clone). Stamped after the diag so the row
    // counts above still see the real result. Opt-in only: an old panel keeps
    // the object shape byte-for-byte.
    if (intent && typeof intent === 'object' && intent.wantJson &&
        String(intent.op || '') === 'acct_read') return acctReadShare(r);
    return r;
  });

  // #2234 quit hook: the local blotter now persists through an append-only
  // journal + a rare snapshot, so whatever is still only in memory has to be
  // forced to disk when the app goes down. Called from main.js's before-quit,
  // with a process-exit backstop for the paths that bypass it.
  try {
    process.on('exit', () => { try { lbFlushSync(); } catch (e) { /* exiting */ } });
  } catch (e) { /* no process hooks (tests) — the explicit lbFlush still works */ }
  // lbFlush stays synchronous (the process-exit hook can use nothing else);
  // lbFlushWait is what a quit that can still await should call.
  return { execIntent, credsStatus, lbFlush: lbFlushSync, lbFlushWait };
}

// ── PURE — HL background REST budgeter (#2008) ──────────────────────────────
// Shell twin of the panel's budgeter: every background /info call rides ONE
// weight-aware paced queue with priority tiers (0 account > 1 chart seeds >
// 2 backfill > 3 catalogs) + a shared 429 backoff-and-resume latch. Signed
// /exchange order sends NEVER queue — they only debit the shared bucket
// (hlBudgetSpend) so heavy order flow pauses background traffic, never the
// reverse. 1000 weight/min vs HL's published 1200/min per-IP budget: the
// head-room absorbs order sends + WS so charts can't starve orders.
function hlInfoWeight(t) {
  if (t === 'l2Book' || t === 'allMids' || t === 'clearinghouseState' ||
      t === 'orderStatus' || t === 'spotClearinghouseState' ||
      t === 'exchangeStatus') return 2;
  if (t === 'userRole') return 60;
  return 20;
}
function hlInfoTier(t) {
  if (t === 'clearinghouseState' || t === 'spotClearinghouseState' ||
      t === 'frontendOpenOrders' || t === 'activeAssetData' ||
      t === 'userRole' || t === 'orderStatus' || t === 'openOrders' ||
      t === 'userFills' || t === 'userFillsByTime' || t === 'historicalOrders' ||
      t === 'userAbstraction')             // #2017: unified-mode probe (10-min cached)
    return 0;
  if (t === 'candleSnapshot') return 1;
  if (t === 'meta' || t === 'spotMeta' || t === 'perpDexs' ||
      t === 'metaAndAssetCtxs' || t === 'spotMetaAndAssetCtxs' ||
      t === 'perpDexLimits') return 3;
  return 2;
}
function hlBudgetMake(capPerMin, now) {
  // #2020 burst bucket (bcap/btokens): the main bucket boots FULL, so cold
  // start / board open could dequeue a 6-9 req/s thundering herd before the
  // per-minute pacing ever bit (field log: 16× /info 429 in minute 0). The
  // small secondary bucket caps instantaneous bursts (~6 heavy calls), then
  // refills at the SAME per-minute rate — steady-state throughput unchanged.
  return { cap: capPerMin, tokens: capPerMin, ts: now || 0,
           q: [[], [], [], []], bkOff: 0, bkN: 0,
           bcap: 120, btokens: 120, bts: now || 0 };
}
function hlBudgetRefill(B, now) {
  const el = now - B.ts;
  if (el > 0) { B.tokens = Math.min(B.cap, B.tokens + el * (B.cap / 60000)); B.ts = now; }
  const eb = now - (B.bts || 0);
  if (eb > 0 && B.bcap > 0) {
    B.btokens = Math.min(B.bcap, (B.btokens || 0) + eb * (B.cap / 60000));
    B.bts = now;
  }
}
function hlBudgetNext(B, now) {
  hlBudgetRefill(B, now);
  if (now < (B.bkOff || 0)) return { item: null, wait: B.bkOff - now };
  for (let t = 0; t < B.q.length; t++) {
    if (!B.q[t].length) continue;
    const it = B.q[t][0];
    const bok = !(B.bcap > 0) || B.btokens >= it.w;   // burst gate (#2020)
    if (B.tokens >= it.w && bok) {
      B.q[t].shift(); B.tokens -= it.w;
      if (B.bcap > 0) B.btokens -= it.w;
      return { item: it, wait: 0 };
    }
    const have = bok ? B.tokens : Math.min(B.tokens, B.btokens || 0);
    return { item: null, wait: Math.max(10, Math.ceil((it.w - have) / (B.cap / 60000))) };
  }
  return { item: null, wait: -1 };
}
function hlBudget429(B, now, hintMs) {
  B.bkN = Math.min((B.bkN | 0) + 1, 6);
  const d = (hintMs > 0) ? hintMs : Math.min(60000, 1000 * Math.pow(2, B.bkN));
  if (now + d > (B.bkOff || 0)) B.bkOff = now + d;
}
function hlBudgetOk(B) { B.bkN = 0; }
function hlBudgetSpend(B, w, now) {
  hlBudgetRefill(B, now);
  B.tokens = Math.max(-B.cap, B.tokens - w);
}
// #2048: freshness gate for the panel-supplied market-order mid hint. The
// panel stamps the intent with its live book mid + Date.now(); the shell
// trusts it ONLY within this window (panel + shell share one PC clock — a
// small abs() pad tolerates IPC scheduling, never a stale book). Returns the
// mid as a string, or null (→ order-critical direct read).
const HL_MID_HINT_MAX_AGE_MS = 2000;
function hlMidHintFresh(mid, ts, now) {
  const n = Number(mid), t = Number(ts);
  if (mid == null || mid === '' || !isFinite(n) || n <= 0) return null;
  if (ts == null || !isFinite(t) || t <= 0) return null;
  if (Math.abs(now - t) > HL_MID_HINT_MAX_AGE_MS) return null;
  return String(mid);
}

// ── PURE — HL per-ADDRESS action rate-limit retry lane (#2012) ──────────────
// HL budgets ACTIONS per address (cumulative 1 action / 1 USDC traded +
// initial buffer) — tiny scalp clips exhaust it fast and no /info pacing
// helps. HL always allows 1 action/s even when the address budget is spent,
// so a limited send auto-retries on a paced 1/s lane (each retry RE-SIGNS
// with a fresh nonce — an in-band "Rate limited" status reply is FINAL for
// that payload). #2016: every distinct user GESTURE is its own FIFO queue
// entry — a newer gesture NEVER drops an older one (the user scales in/out
// with rapid same-symbol clicks; every click is an intended order).
// Supersede survives ONLY inside one gesture's own retry chain (bumping
// e.rseq collapses that gesture's older waiter). Reduce-only/close/cancel
// gestures jump to the FRONT of the queue (closing risk beats adding).
// Total retry latency per send is bounded by HL_ALIM_DEADLINE_MS — on
// expiry the caller gets an honest final `alim` result (toast + optimistic
// badge rollback). Twin lives in panel_terminal.js — keep in lockstep.
// #2020: 6s gave up too early — the address budget refills continuously and
// HL's 1/s lane keeps working, so a burst-limited clip that would succeed a
// few seconds later failed "Rate limited". 20 tries / 20s rides out a deep
// FIFO queue at 1/s; the final failure stays honest (alim toast + rollback).
const HL_ALIM_MAX_TRIES = 20;      // covers the full deadline at the 1/s pace
const HL_ALIM_PACE_MS = 1000;
const HL_ALIM_DEADLINE_MS = 20000; // hard bound per gesture, queue wait included
const HL_ALIM_POLL_MS = 120;       // head-of-queue re-check while waiting
function hlAlimHit(status, message) {
  if ((status | 0) === 429) return true;
  const m = String(message || '');
  return /rate limit/i.test(m) || /too many.*(action|request)/i.test(m);
}
function hlAlimLane() { return { q: [], nextTs: 0, limited: false }; }
// One distinct user gesture = one queue entry, in click order; urgent
// (reduce-only / close / cancel) entries go to the FRONT.
function hlAlimBegin(lane, urgent, now) {
  const e = { rseq: 1, t0: now };
  if (urgent) lane.q.unshift(e); else lane.q.push(e);
  return e;
}
function hlAlimDone(lane, e) {
  const i = lane.q.indexOf(e);
  if (i >= 0) lane.q.splice(i, 1);
}
// Urgent = closes risk: any cancel family action, or an order batch with a
// reduce-only leg.
function hlActionUrgent(a) {
  const t = String((a && a.type) || '');
  if (t.indexOf('cancel') === 0) return true;
  if (t === 'order') {
    for (const o of ((a && a.orders) || [])) if (o && o.r) return true;
  }
  return false;
}
// Decide gesture e's next step at `now`. Returns exactly one of:
//   { wait }              — not this gesture's turn yet (not head / pace clock
//                           busy); re-check after `wait` ms, nothing consumed.
//   { retry: true }       — head of queue + pace slot claimed → send now.
//   { superseded: true }  — a retry of the SAME gesture superseded this waiter.
//   { expired: true }     — attempts or the per-gesture deadline ran out.
function hlAlimNext(lane, e, myRseq, attempt, now, maxTries, deadlineMs) {
  if (myRseq !== (e && e.rseq)) return { retry: false, superseded: true, delay: 0 };
  if (attempt >= (maxTries || HL_ALIM_MAX_TRIES) ||
      now - e.t0 >= (deadlineMs || HL_ALIM_DEADLINE_MS)) {
    return { retry: false, superseded: false, expired: true, delay: 0 };
  }
  if (lane.q[0] !== e) return { retry: false, superseded: false, wait: HL_ALIM_POLL_MS, delay: 0 };
  if (now < (lane.nextTs || 0)) {
    return { retry: false, superseded: false, wait: Math.max(1, (lane.nextTs || 0) - now), delay: 0 };
  }
  lane.nextTs = now + HL_ALIM_PACE_MS;   // claim the 1/s address slot
  return { retry: true, superseded: false, delay: 0 };
}

// ── PURE — HL userFills row → local-blotter fill (#2012, engine twin of
// hl_norm_fill). Spot fee can arrive in the BASE token (feeToken ≠ USDC) →
// converted ×px so the stored fee is always quote-USD. Spot wire coins
// ('@107' / 'HYPE/USDC') map via wireMap when known, else pass through
// raw (engine parity: wire_map.get(coin, coin)).
// #2012 HL backfill pager step (pure): userFillsByTime caps at 2000
// rows/page and fills can share a millisecond, so the pager resumes AT the
// boundary ms (not +1) with exec-id dedupe of the overlap — lossless. A full
// page whose rows all share the start ms cannot prove progress → honest
// possible-gap verdict, never a silent success.
function lbHlPageStep(rows, cur, seen, out) {
  for (const f of rows) {
    const eid = String((f && (f.tid != null ? f.tid : f.hash)) || '');
    if (eid && seen[eid]) continue;
    if (eid) seen[eid] = 1;
    out.push(f);
  }
  if (rows.length < 2000) return { done: true, gap: false, next: cur };
  const lastTs = Math.floor(Number(rows[rows.length - 1].time) || 0);
  if (!(lastTs > cur)) return { done: true, gap: true, next: cur };
  return { done: false, gap: false, next: lastTs };
}
function lbHlCoinIsSpot(coin) {
  const c = String(coin || '');
  return c.charAt(0) === '@' || c.indexOf('/') >= 0;
}
function lbNormHlFill(f, wireMap) {
  if (!f || typeof f !== 'object') return null;
  const px = lbNum(f.px);
  const qty = lbNum(f.sz);
  if (!px || !qty || !(Number(px) > 0) || !(Number(qty) > 0)) return null;
  const coin = String(f.coin || '');
  if (!coin) return null;
  const spot = lbHlCoinIsSpot(coin);
  const sym = spot ? (((wireMap || {})[coin]) || coin) : coin;
  let fee = Number(lbNum(f.fee) || '0');
  if (!isFinite(fee)) fee = 0;
  const feeTok = String(f.feeToken || '');
  if (feeTok && feeTok !== 'USDC') fee = fee * Number(px);
  return {
    venue: 'hyperliquid',
    market: spot ? 'spot' : 'futures',
    symbol: sym,
    side: String(f.side) === 'B' ? 'buy' : 'sell',
    posSide: '', order_px: '',
    exec_px: px, qty: qty,
    value: lbFmt(Number(px) * Number(qty)),
    fee: fee ? lbFmt(fee) : '0',
    closed_pnl: lbNum(f.closedPnl) || '0',
    kind: 'trade', funding: '0',
    ts: Math.floor(Number(f.time) || 0),
    exec_id: String(f.tid != null ? f.tid : (f.hash || '')),
  };
}

module.exports = {
  // pure (parity/validation tested under plain node)
  PHEMEX_BASE,
  TRADE_VENUES,
  tnSlotNorm,
  decParts,
  futReal,
  spotToScaled,
  phemexSign,
  phemexExpiry,
  phemexFuturesOrderBody,
  phemexSpotOrderBody,
  canonJson,
  buildPhemexRequests,
  phemexSwitchPosModeStep,
  phemexHedgeRecoveryFlow,
  phemexPositionRows,
  findPosition,
  validateIntent,
  sltpTriggerOk,
  tradeViaFromAgent,
  pingRtTarget,
  warmTargetsFor,
  rewarmDue,
  WARM_MIN_GAP_MS,
  phemexErrorMessage,
  phemexSymbolRequired,
  // shared keep-alive agent cache (used by main.js's native-WS bridge too)
  sharedKeepAliveAgent,
  flushKeepAliveAgents,
  kaAgentKey,
  httpRetryLimit,
  httpTmoAt,
  staleSocketError,
  connectPhaseError,
  httpRetryAllowed,
  KEEPALIVE_MSECS,
  KA_MAX_SOCKETS,
  // pure — Lighter native (engine-parity helpers, WASM-independent)
  LIGHTER_HOST,
  LIGHTER_CHAIN_ID,
  LIGHTER_DEFAULT_KEY_INDEX,
  ltParseKey,
  ltCoi,
  ltUnits,
  ltBoundUnits,
  // pure — venue time sync (offset math + probe registry)
  VENUE_TIME_PROBES,
  venueTimeProbe,
  venueTimeProbeKey,
  venueClkOffset,
  venueStampMs,
  venueStampSec,
  // pure — multi-venue (Binance / Bybit / OKX / Gate / Bitget)
  decNorm,
  bnNum,
  decFmt,
  truncInt,
  formEnc,
  binanceSign,
  binanceErrorMessage,
  binanceOrderParams,
  binanceAlgoOrderParams,
  binancePositionRows,
  unreadableBodyMsg,
  bybitSign,
  bybitErrorMessage,
  bybitOrderBody,
  bybPositionRows,
  okxSign,
  okxTs,
  okxErrorMessage,
  okxContracts,
  okxClOrdId,
  okxOrderBody,
  okxAlgoBody,
  okxBaseQty,
  okxPositionRows,
  okxCancelGone,
  gateBodyHash,
  gateSign,
  gateErrorMessage,
  gateContracts,
  gateText,
  gateOrderBody,
  gatePoRule,
  gatePoBody,
  gateBaseQty,
  gatePositionRows,
  gateCancelGone,
  bitgetSign,
  bitgetErrorMessage,
  bitgetClOrdId,
  bitgetOrderBody,
  bitgetPlanBody,
  bitgetPositionRows,
  bitgetCancelGone,
  // pure — KuCoin / BitMEX
  kcSign,
  kcPassphraseSig,
  kcErrorMessage,
  kcClOrdId,
  kcContracts,
  kcBaseQty,
  kcSpotOrderBody,
  kcFutOrderBody,
  kcStopDir,
  kcPositionRows,
  kucoinCancelGone,
  pyFloat,
  bmxSign,
  bmxExpires,
  bmxClOrdId,
  bmxContracts,
  bmxBaseQty,
  bmxOrderBody,
  bmxPositionRows,
  bitmexCancelGone,
  mexcSpotSign,
  mexcFutSign,
  mexcFutParamStr,
  mexcErrorMessage,
  mexcIsRestrictedErr,
  mexcIsQtyScaleErr,
  mexcQtyScale,
  mexcQtyFloorScale,
  mexcClOrdId,
  mexcFutSide,
  mexcContracts,
  mexcBaseQty,
  mexcSpotOrderParams,
  mexcFutOrderBody,
  mexcPlanTrend,
  mexcPlanBody,
  mexcPositionRows,
  mexcCancelGone,
  // pure — Kraken (venue #14, engine kr_* golden parity)
  KRAKEN_SPOT_HOST,
  KRAKEN_FUT_HOST,
  krSpotSign,
  krFutSign,
  krFutSignPath,
  krLevPrefPick,
  krClOrdId,
  krDecStep,
  krQtyFloor,
  krFutOrderParams,
  krSpotOrderParams,
  krPositionRows,
  // pure — Kraken private WS (#1804)
  KRAKEN_SPOT_WS_URL,
  KRAKEN_FUT_WS_URL,
  KR_WS_ENABLE_HINT,
  krFutWsSign,
  krWsPermMsg,
  KR_WS_SPOT_GONE,
  krWsFutOrderRest,
  krWsFutPosRest,
  krWsFlexRest,
  krWsSpotHolds,
  krWsSpotBalanceEx,
  krWsSpotOpenOrders,
  // pure — Kraken optimistic REST-ack echo (#1822)
  KR_SYN_TTL_MS,
  krSynSpotOrder,
  krSynFutOrder,
  krSynPrune,
  krSynCarry,
  krSynSweepSymbol,
  // pure — Kraken post-trade fast lane (#1826)
  KR_CONFIRM_DELAY_MS,
  KR_CONFIRM_MIN_GAP_MS,
  KR_CONFIRM_ORDER_GRACE_MS,
  KR_AUDIT_BIRTH_GRACE_MS,
  krLseq,
  krPushMark,
  krPushDrain,
  krFutPosSig,
  krLedgerFreshIds,
  krConfirmKick,
  krConfirmFire,
  krConfirmDone,
  krAssetWsName,
  krBalanceExTotals,
  krOrdersReconcile,
  // pure — #1870 fill-consumption badge removal + stale-snapshot auditor gate
  krFillOrderApply,
  krFutFillOrderApply,
  krOrderFilled,
  krExecsOrderFirst,
  krConsumedNote,
  krConsumedTake,
  krConsumedPrune,
  KR_CONSUMED_TTL_MS,
  // pure — #1887 permanent closed-order set + oid→symbol memory
  KR_CLOSED_MAX,
  krClosedAdd,
  krClosedHas,
  // pure — #1890 exactly-once fill ingest
  krFillIngestGate,
  krBalRowRefs,
  KR_OIDSYM_MAX,
  krOidSymNote,
  krOidSymGet,
  KR_SYMFIX_SCAN_MAX,
  krFillsSymBackfill,
  krFillDirsPrune,
  KR_FILL_CLAMP_GRACE_MS,
  krFillTotalsApply,
  krTotalsAudit,
  krFillTouchPrune,
  krAuditGate,
  // pure — #1876 gone-order tombstones (no badge resurrection)
  KR_TOMB_TTL_MS,
  KR_TOMB_SNAP_TTL_MS,
  krPushFillRow,
  krTombAdd,
  krTombHit,
  krTombSweep,
  krTombConfirm,
  // pure — Kraken private-REST points ledger (#1832)
  KR_LEDGER_MAX,
  KR_LEDGER_DECAY,
  KR_LEDGER_FLOOR,
  KR_QUERY_WAIT_MAX_MS,
  KR_CANCEL_RETRY_MS,
  krCallCost,
  krLedgerNew,
  krLedgerGate,
  krLedgerDrain,
  krLedgerPts,
  krIsRateLimited,
  // pure — Kraken spot TRADING rate counter (#1839)
  KR_TRADE_MAX,
  KR_TRADE_DECAY,
  KR_TRADE_FLOOR,
  KR_ORDER_PACE_MAX_MS,
  krCancelPenalty,
  krTradeLedgerNew,
  krTradeSpend,
  krTradeGate,
  krTradePts,
  // pure — Kraken native fills cache (#1814)
  krWsSpotFillRow,
  krRestSpotWsRow,
  krRestFutWsRow,
  krSeedSpotNext,
  krSeedFutNext,
  krWsFutFillRow,
  krPushFutFillRow,
  KR_FILLS_TS_SKEW_MS,
  krFillsCachePush,
  krFillsWindow,
  krFillsScopeReady,
  // pure — Kraken private-WS lag recorder (#1835)
  krLagNew,
  krLagRec,
  krLagPct,
  krLagSnap,
  // pure — #1943 Binance shell user-data push
  BN_SPOT_WSAPI_URL,
  BN_FUT_WS_BASE,
  BN_LK_KEEPALIVE_MS,
  BN_UDS_STALE_MS,
  BN_UDS_FILLS_CAP,
  bnSpotSubscribeFrame,
  bnWsEvent,
  bnOrdEffect,
  bnFillIngest,
  // pure — #1969 device-local blotter
  lbNum,
  lbFmt,
  lbMoney,
  lbKrAsset,
  lbKrFeeAlt,
  lbIsoMs,
  lbNormKrWsSpot,
  lbNormKrWsFut,
  lbNormBnFut,
  lbNormBnSpot,
  lbNormBnFutRest,
  lbNormBnSpotRest,
  lbFillKey,
  lbScopeMerge,
  lbHwm,
  lbPruneRows,
  lbReconstruct,
  lbGroupKey,
  lbTradeOrder,
  lbReplay,
  lbRingFrom,
  lbJrnLine,
  lbJrnParse,
  lbPerfNew,
  lbPerfAdd,
  lbHlCoinIsSpot,
  lbNormHlFill,
  lbHlPageStep,
  lbNormBybFill,
  bybWsAuthSig,
  bitgetWsLoginSig,
  bybOrdEffect,
  // pure — #2230 no-news local-blotter drain gate
  LB_DRAIN_IDLE_MS,
  lbDrainSkip,
  lbSrcTouch,
  lbSrcVer,
  // pure — #2230 public-data share guard (single-flight + start-stamped memo)
  CAT_SHARE_MEMO_MS,
  CAT_SHARE_MIN_BYTES,
  catShareBytes,
  catShareGuard,
  // pure — acct_read rate-limit guard (#1724)
  ACCT_RL_COOLDOWN_MS,
  ACCT_READ_MEMO_MS,
  acctRlHit,
  acctRlWaitMs,
  acctReadGuard,
  // pure — #2131 hot-venue acct-read priority
  ACCT_HOT_MS,
  ACCT_IDLE_YIELD_MS,
  acctPrioGate,
  // #2281 shared-pool admission + union pacing
  ACCT_READ_MEMO_MAX_MS,
  acctMemoMs,
  ACCT_POOL_MAX_TOTAL,
  ACCT_POOL_MAX_VENUE,
  ACCT_POOL_OVERFLOW_MS,
  acctPoolGate,
  PHEMEX_ACCT_LEG_MS,
  PHEMEX_ACCT_DEADLINE_MS,
  // pure — #2168 re-import reservation on the kraken rate-points ledger
  KR_RESV_TTL_MS,
  krResvNew,
  krResvAcquire,
  krResvRelease,
  krResvHeld,
  // pure — #2008 HL background REST budgeter
  hlInfoWeight,
  hlInfoTier,
  hlBudgetMake,
  hlBudgetRefill,
  hlBudgetNext,
  hlBudget429,
  hlBudgetOk,
  hlBudgetSpend,
  // pure — #2048 order-critical mid hint freshness gate
  HL_MID_HINT_MAX_AGE_MS,
  hlMidHintFresh,
  // pure — HL per-address action rate-limit retry lane (#2012)
  HL_ALIM_MAX_TRIES,
  HL_ALIM_PACE_MS,
  hlAlimHit,
  hlAlimLane,
  hlAlimBegin,
  hlAlimDone,
  hlActionUrgent,
  hlAlimNext,
  // pure — #2026 Binance IP-ban freeze latch
  BN_BAN_HOSTS,
  BN_BAN_PAD_MS,
  BN_BAN_BACKOFF0_MS,
  BN_BAN_BACKOFF_MAX_MS,
  bnBanParseUntil,
  bnBanTimeTxt,
  bnBanMsgFor,
  bnBanRegNote,
  bnBanGateErr,
  // pure — clock-probe 429 backoff (#2012)
  CLK_BO_BASE_MS,
  CLK_BO_MAX_MS,
  clkProbe429,
  clkProbeOk,
  clkProbeBlocked,
  // pure — clock-probe hygiene + -1021 self-heal (#2192)
  CLK_RTT_SANE_MS,
  CLK_PROBE_TRIES,
  CLK_SLOW_RETRY_MS,
  CLK_PROBE_BUDGET_MS,
  clkProbeFold,
  clkTsReject,
  // runtime
  createTradeNative,
};
