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

// --- Bybit pure builders ----------------------------------------------------
function bybitSign(secret, tsMs, apiKey, recvWindow, payload) {
  const msg = String(tsMs) + String(apiKey) + String(recvWindow) + String(payload);
  return crypto.createHmac('sha256', String(secret)).update(msg, 'utf8').digest('hex');
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
// Futures ws/v1 `fills` feed row → cache row. fill_id keys the dedupe — the
// SAME id REST /derivatives/api/v3/fills publishes, so engine-side dedupe
// keys stay identical to engine-fetched copies.
function krWsFutFillRow(f) {
  if (!f || typeof f !== 'object') return null;
  if (!String(f.fill_id || '')) return null;
  if (!(Number(f.qty) > 0)) return null;
  return { id: String(f.fill_id), ts: Number(f.time) || 0, raw: f };
}
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
  let n = 0;
  for (const oid of Object.keys(orders || {})) {
    const o = orders[oid] || {};
    const ts = o._synTs;
    if (ts != null && now - ts > KR_SYN_TTL_MS && o._omitTs > 0) { delete orders[oid]; n += 1; }
  }
  return n;
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
function krPushMark(P, key, kind, id) {
  if (!P[key]) P[key] = { kinds: {} };
  const k = String(kind || 'ledger');
  P[key].kinds[k === 'ordgone' ? 'order' : k] = 1;
  if (id != null && k === 'fill') {
    if (!P[key].fids) P[key].fids = [];
    const s = String(id);
    if (P[key].fids.length < KR_PUSH_FIDS_CAP && P[key].fids.indexOf(s) < 0) {
      P[key].fids.push(s);
    }
  }
  if (id != null && k === 'ordgone') {
    if (!P[key].goids) P[key].goids = [];
    const g = String(id);
    if (P[key].goids.length < KR_PUSH_FIDS_CAP && P[key].goids.indexOf(g) < 0) {
      P[key].goids.push(g);
    }
  }
}
function krPushDrain(P, seqOf, nowMs) {
  const out = [];
  for (const key of Object.keys(P)) {
    const ix = key.indexOf('|');
    const ev = { venue: 'kraken', slot: key.slice(0, ix), scope: key.slice(ix + 1),
                 kinds: Object.keys(P[key].kinds).sort(),
                 seq: seqOf ? (seqOf(key) | 0) : 0, ts: nowMs };
    if (P[key].fids && P[key].fids.length) ev.fids = P[key].fids.slice();
    if (P[key].goids && P[key].goids.length) ev.goids = P[key].goids.slice();
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
  delete orders[oid]._synTs;   // venue echo confirms the optimistic row
  orders[oid]._updTs = now;
  return 'upd';
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
function krTombAdd(tombs, oid, now) {
  const t = (tombs && typeof tombs === 'object') ? tombs : {};
  if (oid != null && oid !== '') t[String(oid)] = +now;
  return t;
}
function krTombHit(tombs, oid, now) {
  const ts = tombs && tombs[String(oid)];
  return ts != null && (+now - ts) <= KR_TOMB_TTL_MS;
}
function krTombSweep(tombs, now) {
  const t = (tombs && typeof tombs === 'object') ? tombs : {};
  for (const k of Object.keys(t)) {
    if (+now - t[k] > KR_TOMB_TTL_MS) delete t[k];
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
function krFillTotalsApply(totals, e) {
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
function krTotalsAudit(local, audit, touch, now, graceMs, eps) {
  const g = (graceMs == null) ? KR_FILL_TOUCH_GRACE_MS : graceMs;
  const e = (eps == null) ? KR_AUDIT_REL_EPS : eps;
  const out = {}, div = [];
  const keys = {};
  for (const k of Object.keys(audit || {})) keys[k] = 1;
  for (const k of Object.keys(local || {})) keys[k] = 1;
  for (const a of Object.keys(keys)) {
    const fresh = touch && touch[a] != null && (now - touch[a]) <= g;
    const lv = local && local[a] != null ? Number(local[a]) : null;
    const av = audit && audit[a] != null ? Number(audit[a]) : null;
    if (fresh && lv != null) { out[a] = String(local[a]); continue; }
    if (av == null) {         // local-only asset past grace: auditor wins (drop)
      if (lv != null && Math.abs(lv) > e) div.push(a);
      continue;
    }
    out[a] = String(audit[a]);
    if (lv == null || Math.abs(lv - av) > e * Math.max(1, Math.abs(av))) div.push(a);
  }
  return { totals: out, div: div };
}
// Bounded prune for the per-asset fill-touch map (entries expire with the
// grace window; the map only ever holds a scalp session's active assets).
function krFillTouchPrune(touch, now, graceMs) {
  const g = (graceMs == null) ? KR_FILL_TOUCH_GRACE_MS : graceMs;
  for (const a of Object.keys(touch || {})) {
    if (!(now - touch[a] <= g)) delete touch[a];
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
  const memo = {};       // venue|credSlot → { ts, r }
  let readSeq = 0;       // #1853: monotonic ISSUANCE seq stamped on results
  const guarded = async function (intent) {
    const venue = String((intent && intent.venue) || '');
    const key = venue + '|' + String((intent && intent.credSlot) || venue);
    const t0 = now();
    const left = (rlUntil[venue] || 0) - t0;
    if (left > 0) {
      emit('paced', { venue: venue, retryInMs: left });
      return { ok: false, rateLimited: true, retryInMs: left,
               message: 'Rate limited — pacing reads, retry in ' + Math.ceil(left / 1000) + 's' };
    }
    const m = memo[key];
    if (m && t0 - m.ts < ACCT_READ_MEMO_MS) { emit('memo', { venue: venue }); return m.r; }
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
      const r = await runRaw(intent);
      if (r && typeof r === 'object' && r.readSeq == null) r.readSeq = issSeq;
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
      memo[key] = { ts: now(), r: r };
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
  return guarded;
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
    return { ok: true, tail: venues[venue].tail };
  }
  function credsWipe(venue) {
    const venues = credsLoadAll();
    if (venue) delete venues[venue];
    credsSaveAll(venues);
    try { if (venue) krWsCloseAll(venue); else for (const k of Object.keys(krWsSessions)) krWsClose(k); } catch (e) { /* no session */ }
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
  function httpJson(host, method, reqPath, query, bodyStr, headers, route, maxBytes) {
    const cap = (Number.isFinite(maxBytes) && maxBytes > 0) ? maxBytes : 262144;
    const attempt = () => new Promise((resolve, reject) => {
      const diagT0 = Date.now();
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
        headers: h, timeout: HTTP_TIMEOUT_MS,
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
    return attempt().catch((e) => {
      if (httpRetryAllowed(method, e, !!(e && e.reqSent))) {
        // Stale-socket failure → flush the agent's FREE pool first so the
        // retry is guaranteed a fresh socket (LIFO could otherwise hand it
        // another idle corpse the venue/CF killed in the same sweep).
        if (staleSocketError(e)) {
          const ag = agentFor(route);
          if (ag && ag.agent) evictFreeSockets(ag.agent);
          else if (ag && !ag.refuse) evictFreeSockets(sharedKeepAliveAgent(null, null));
        }
        return attempt();
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
    if (!force && Date.now() - st.ts < TIMESYNC_TTL_MS) return st.offsetMs;
    st.ts = Date.now();                // stamp first — one probe per TTL even on failure
    try {
      const t0 = Date.now();
      const r = await httpJson(spec.host, 'GET', spec.path, '', null, {}, route);
      const t1 = Date.now();
      let sv = null;
      if (spec.dateHeader) {
        // HTTP Date header (BitMEX — no time endpoint): second resolution,
        // centered by +500ms.
        const p = r.date ? Date.parse(r.date) : NaN;
        if (isFinite(p)) sv = p + 500;
      } else {
        sv = spec.ext(JSON.parse(r.text));
      }
      if (isFinite(sv) && sv > 1e12) st.offsetMs = venueClkOffset(sv, t0, t1);
      tdiag('clk', 'probe', { k: key, venue: venue, offsetMs: st.offsetMs, ms: t1 - t0 });
    } catch (e) {
      tdiag('clk', 'probe-fail', { k: key, venue: venue, msg: (e && e.message) || 'error' });
      /* keep last offset (0 initially — engine-parity behavior) */
    }
    return st.offsetMs;
  }

  // --- products cache (spot base valueScale) -------------------------------
  // spotSpec THROWS on catalog fetch/parse failure (network, truncation, bad
  // JSON) and returns null ONLY for a successfully-loaded catalog that lacks
  // the symbol — the call site maps the throw to an honest "couldn't load
  // catalog" message instead of "Unknown spot symbol X".
  // The full Phemex catalog measured ~2.5 MB (2026-07); pass an 8 MB cap so
  // the default 256 KB httpJson cap doesn't silently truncate it.
  const products = { spot: null, curScales: null, raw: null, ts: 0 };
  async function phemexProducts(route) {
    if (!products.spot || Date.now() - products.ts > PRODUCTS_TTL_MS) {
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
      products.ts = Date.now();
    }
    return products;
  }
  async function spotSpec(symbol, route) {
    const p = await phemexProducts(route);
    return p.spot[symbol] || null;
  }

  // --- signed request runner ------------------------------------------------
  async function signedRequest(creds, step, route) {
    const offMs = await ensureVenueTime('phemex', null, route);
    const bodyStr = step.body != null ? canonJson(step.body) : '';
    const expiry = phemexExpiry(null, offMs / 1000);
    const headers = {
      'x-phemex-access-token': creds.key,
      'x-phemex-request-signature': phemexSign(creds.secret, step.path, step.query || '', expiry, bodyStr),
      'x-phemex-request-expiry': String(expiry),
    };
    let r;
    try {
      r = await httpJson(PHEMEX_HOST, step.method, step.path, step.query || '', bodyStr || null, headers, route);
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

  async function bnRequest(creds, method, market, reqPath, params, route, maxBytes) {
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
    const fetchPos = async () => {
      // v3 + explicit symbol: the symbol-less v2 call returns EVERY listed
      // contract (200KB+, past the httpJson byte cap → truncated body).
      const r = await bnRequest(creds, 'GET', 'futures', '/fapi/v3/positionRisk',
                                [['symbol', String(intent.symbol)]], route);
      if (!r.ok) return r;
      return { ok: true, rows: binancePositionRows(r.data) };
    };
    if (intent.op === 'order') {
      return bnPlace(creds, route, market, intent.symbol, intent.side, intent.type,
                     intent.qty, intent.price, intent.clOrdID,
                     { reduceOnly: !!intent.reduceOnly, trigger: intent.trigger });
    }
    if (intent.op === 'cancel') {
      const reqPath = market === 'futures' ? '/fapi/v1/order' : '/api/v3/order';
      const r = await bnRequest(creds, 'DELETE', market, reqPath,
                                [['symbol', intent.symbol], ['orderId', intent.orderID]], route);
      if (!r.ok && market === 'futures' && (r.code === -2011 || r.code === -2013)) {
        // Conditionals carry algoIds the plain endpoint doesn't know.
        const r2 = await bnRequest(creds, 'DELETE', 'futures', '/fapi/v1/algoOrder',
                                   [['algoId', intent.orderID]], route);
        if (r2.ok) return { ok: true, cancelled: intent.orderID };
        return r;                       // surface the ORIGINAL (clearer) error
      }
      if (!r.ok) return r;
      return { ok: true, cancelled: intent.orderID };
    }
    if (intent.op === 'cancel_all') {
      if (market === 'futures') {
        const r = await bnRequest(creds, 'DELETE', 'futures', '/fapi/v1/allOpenOrders',
                                  [['symbol', intent.symbol]], route);
        if (!r.ok) return r;
        // Algo (conditional) orders are NOT swept by allOpenOrders.
        const ra = await bnRequest(creds, 'DELETE', 'futures', '/fapi/v1/algoOpenOrders',
                                   [['symbol', intent.symbol]], route);
        if (!ra.ok && ra.code !== -2011 && ra.code !== -2013) return ra;
        return { ok: true, cancelled: 'all' };
      }
      const r = await bnRequest(creds, 'DELETE', 'spot', '/api/v3/openOrders',
                                [['symbol', intent.symbol]], route);
      if (!r.ok && r.code !== -2011) return r;   // -2011 = nothing open — fine
      return { ok: true, cancelled: 'all' };
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

  // --- KuCoin ----------------------------------------------------------------
  const KC_NATIVE_LEVERAGE = '10';   // engine KC_DEFAULT_LEVERAGE parity — leverage rides each order
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
                                  KC_NATIVE_LEVERAGE,
                                  { reduceOnly: !!f.reduceOnly,
                                    trigger: isStop ? f.trigger : null,
                                    triggerDir: trigDir });
      const r = await kcRequest(creds, 'POST', 'futures', '/api/v1/orders', null, body, route);
      if (!r.ok) return r;
      const oid = String((((r.data || {}).data) || {}).orderId || '');
      if (isStop) return { ok: true, orderID: oid ? 'st:' + oid : null, clOrdID: clOrdID };
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
  async function krRequest(creds, method, market, path, params, route, _nretry, _cxl0, _pri) {
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
      for (;;) {
        const g = krLedgerGate(led, krCC.cls, krCC.cost, Date.now());
        if (g.send) break;
        tdiag('trade', 'kr_budget', { k: 'kraken', p: path,
          act: g.skip ? 'skip' : 'defer', waitMs: g.waitMs,
          pts: Math.round(krLedgerPts(led, Date.now()) * 10) / 10 });
        if (g.skip) {
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
        return krRequest(creds, method, market, path, params, route, true, _cxl0, _pri);
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
                             _nretry, t0, _pri);
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
  function krTombBlock(sc, oid, w) {
    if (!sc || !krTombHit(sc.tombs, oid, Date.now())) return false;
    const now = Date.now();
    if (now - (sc._tombDiagT || 0) > 5000) {
      sc._tombDiagT = now;
      try { tdiag('acct', 'kr_tomb_block', { w: w, oid: String(oid).slice(0, 24) }); } catch (e) { /* diag-only */ }
    }
    return true;
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
      try { pushLedgerCb(ev); } catch (e) { /* window gone mid-send */ }
      tdiag('acct', 'kr_push', { s: ev.scope, q: ev.seq, k: ev.kinds.join(',') });
    }
  }
  function krPushSc(scope, kind, id) {
    // #1876: EVERY gone-order removal tombstones here (single choke point —
    // fill-consumed, cancel-ACKed, WS-gone and audit-confirmed deletes all
    // push 'ordgone'), so lagging snapshots/echoes can't resurrect the row.
    // Runs BEFORE the push-wiring guard: web/no-push shells tombstone too.
    if (scope && String(kind) === 'ordgone' && id != null && id !== '') {
      scope.tombs = krTombAdd(scope.tombs, String(id), Date.now());
    }
    if (!pushLedgerCb || !scope || !scope._pk) return;
    krPushMark(krPushPend, scope._pk, kind, id);
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
              S.tombs = krTombConfirm(S.tombs, snapIds, snapT0);
            }
            // #1814: the snap_trades snapshot IS the fills seed — until it
            // lands, fills_read must NOT report this scope (an empty read
            // would advance the panel cursor past the seed window).
            if (S.fills) S.fills.seeded = true;
          }
          for (const e of (msg.data || [])) {
            if (!e || typeof e !== 'object') continue;
            // #1814: trade executions feed the native fills cache (dedupe
            // by exec_id — snapshot + live overlap is a no-op). Snapshot
            // trade rows may carry NO order_status: never let one land in
            // the open-orders map as a phantom row.
            const fr = krWsSpotFillRow(e);
            if (fr) krFillsCachePush(S.fills, fr);
            // #1864 fills-first posrow: a LIVE trade execution applies its
            // balance delta to the totals map synchronously (buy +base/-cost,
            // sell -base/+cost, fees off their own asset) — the posrow moves
            // NOW, the ~3-6s-late balances echo / REST auditor only confirms.
            // Touched assets stamp a grace window so a venue snapshot taken
            // BEFORE this fill can't clobber the local value right back.
            if (fr && !lagSnapFrame && S.totals) {
              const touched = krFillTotalsApply(S.totals, e);
              if (touched.length) {
                if (!S.fillTouch) S.fillTouch = {};
                const tnow = Date.now();
                for (const a of touched) S.fillTouch[a] = tnow;
                krFillTouchPrune(S.fillTouch, tnow);
                krLseq(S); krPushSc(S, 'bal');   // #1867 fills-first posrow beat
              }
            }
            if (fr && !lagSnapFrame) { krLseq(S); krPushSc(S, 'fill', fr.id); }   // #1867 push-driven chime (+#1870 per-fill id) — seq MUST advance per live fill or back-to-back fill-only frames dedupe as stale
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
              const eff = krTombBlock(S, String(e.order_id || ''), 'sfill')
                ? null : krFillOrderApply(S.orders, e, Date.now());
              // #1874: fill-consumed rows push the gone oid — every panel
              // window tombstones the badge in the same push apply pass
              if (eff) { krLseq(S); krPushSc(S, eff === 'gone' ? 'ordgone' : 'order', eff === 'gone' ? String(e.order_id || '') : null); }   // #1860/#1867/#1874
              continue;
            }
            const oid = String(e.order_id || '');
            if (!oid) continue;
            if (KR_WS_SPOT_GONE[String(e.order_status || '').toLowerCase()]) {
              delete S.orders[oid];
              krLseq(S); krPushSc(S, 'ordgone', oid);   // #1874 WS-gone badge fast path
              continue;
            } else {
              // #1876: lagging echo/snapshot row for a just-removed order —
              // the tombstone wins, never a badge resurrection
              if (krTombBlock(S, oid, 'sord')) continue;
              // delta frames carry partial fields — merge onto the row
              S.orders[oid] = Object.assign({}, S.orders[oid] || {}, e);
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
            // #1864: delta echoes lag fills by seconds — an asset the local
            // fill math touched within the grace keeps the LOCAL value
            // (snapshot frames reset the map, so they always apply).
            if (!balSnap && S.fillTouch && S.fillTouch[a] != null &&
                Date.now() - S.fillTouch[a] <= KR_FILL_TOUCH_GRACE_MS) continue;
            S.totals[a] = r.balance;
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
            F.tombs = krTombConfirm(F.tombs, snapIds, snapT0);
          }
          for (const o of (msg.orders || [])) {
            const oid = String((o || {}).order_id || '');
            if (oid) {
              if (krTombBlock(F, oid, 'fsnap')) continue;   // #1876 just-removed — no resurrection
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
                krLseq(F); krPushSc(F, 'order');   // #1860 / #1867
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
              const eff = krTombBlock(F, String((f || {}).order_id || ''), 'ffill')
                ? null : krFutFillOrderApply(F.orders, f, Date.now());
              // #1874: fill-consumed rows push the gone oid (badge fast path)
              if (eff) { krLseq(F); krPushSc(F, eff === 'gone' ? 'ordgone' : 'order', eff === 'gone' ? String(f.order_id || '') : null); }   // #1860/#1867/#1874
              // per-fill push id (#1870): each live fill rides the event so
              // the panel chime plays per fill at push time
              krLseq(F); krPushSc(F, 'fill', fr.id);   // seq advances per live fill (snapshot rows never bump)
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
            if (t === 'limit') {
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
        if (t === 'limit' && sessO) {   // #1822 optimistic echo (REST ack)
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
        if (sessF) {
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
        if (sessF) { krSynSweepSymbol(sessF.fut.orders, intent.symbol, 'instrument'); krLseq(sessF.fut); krPushSc(sessF.fut, 'order'); }   // #1867
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
          for (const k of Object.keys(sessA.spot.orders || {})) delete sessA.spot.orders[k];
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
  async function hlInfo(body, route) {
    let r;
    try {
      r = await httpJson(HL_HOST, 'POST', '/info', '', JSON.stringify(body), {}, route);
    } catch (e) { return transportFail(e, 'Hyperliquid'); }
    if (r.status === 429) return { ok: false, message: 'Rate limited by Hyperliquid — retry shortly' };
    if (r.status !== 200) return { ok: false, message: 'Hyperliquid returned HTTP ' + r.status };
    try { return { ok: true, data: JSON.parse(r.text) }; } catch (e) {
      return { ok: false, message: 'Hyperliquid returned malformed JSON' };
    }
  }

  async function hlExchange(creds, action, route) {
    const nonce = dexSign.hlNextNonce();
    let sig;
    try { sig = dexSign.hlSignAction(String(creds.secret).trim(), action, nonce); }
    catch (e) { return { ok: false, message: 'Hyperliquid signing failed: ' + ((e && e.message) || 'error') }; }
    const payload = { action: action, nonce: nonce, signature: sig, vaultAddress: null };
    let r;
    try {
      r = await httpJson(HL_HOST, 'POST', '/exchange', '', JSON.stringify(payload), {}, route);
    } catch (e) { return transportFail(e, 'Hyperliquid'); }
    if (r.status === 429) return { ok: false, message: 'Rate limited by Hyperliquid — retry shortly' };
    let data;
    try { data = JSON.parse(r.text); } catch (e) {
      return { ok: false, message: 'Hyperliquid returned HTTP ' + r.status };
    }
    const res = dexSign.hlExchangeResult(data);
    if (!res.ok) return { ok: false, message: res.message };
    return { ok: true, st: res.st };
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
      mid = await hlMid(spec.wire, route);
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
                     { reduceOnly: !!intent.reduceOnly, trigger: intent.trigger });
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
    const sa = await bnRequest(creds, 'GET', 'spot', '/api/v3/account',
                               [['omitZeroBalances', 'true']], route);
    if (!sa.ok) return sa;
    const so = await bnRequest(creds, 'GET', 'spot', '/api/v3/openOrders', [], route);
    if (!so.ok) return so;
    const fb = await bnRequest(creds, 'GET', 'futures', '/fapi/v2/balance', [], route);
    if (!fb.ok) return fb;
    // Symbol-less positionRisk returns EVERY listed contract (200KB+) —
    // raise the httpJson byte cap so JSON.parse never sees a truncated body
    // (shell-httpjson convention; the engine twin parses the same payload).
    const pos = await bnRequest(creds, 'GET', 'futures', '/fapi/v2/positionRisk',
                                [], route, 4 * 1024 * 1024);
    if (!pos.ok) return pos;
    const fo = await bnRequest(creds, 'GET', 'futures', '/fapi/v1/openOrders', [], route);
    if (!fo.ok) return fo;
    const ao = await bnRequest(creds, 'GET', 'futures', '/fapi/v1/openAlgoOrders', [], route);
    if (!ao.ok) return ao;
    const arr = (r) => (Array.isArray(r.data) ? r.data : []);
    return { ok: true,
             spotAcct: sa.data || {},
             spotOrders: arr(so),
             futBalance: arr(fb),
             positions: arr(pos),
             futOrders: arr(fo),
             algoOrders: arr(ao) };
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
    const acct = await signedRequest(creds, {
      method: 'GET', path: '/g-accounts/accountPositions',
      query: 'currency=USDT', body: null }, route);
    if (!acct.ok) return acct;
    let fo = await signedRequest(creds, {
      method: 'GET', path: '/g-orders/activeList',
      query: 'currency=USDT', body: null }, route);
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
        const rs = await signedRequest(creds, {
          method: 'GET', path: '/g-orders/activeList',
          query: 'symbol=' + encodeURIComponent(p.symbol), body: null }, route);
        if (rs.ok) futRows = futRows.concat((rs.data && rs.data.rows) || (Array.isArray(rs.data) ? rs.data : []));
      }
    } else return fo;
    // Wallets BEFORE spot orders (#1722): the spot symbol-required fallback
    // derives its symbols from nonzero wallets × the products catalog.
    const wl = await signedRequest(creds, {
      method: 'GET', path: '/spot/wallets', query: '', body: null }, route);
    if (!wl.ok) return wl;
    // Shape-tolerant: /spot/wallets data is a bare list today, but a wrapped
    // {rows:[…]} variant must not silently empty the spot holdings (the DOM
    // posrow derives from these rows — engine twin unwraps identically).
    const wallets = Array.isArray(wl.data) ? wl.data
      : (wl.data && Array.isArray(wl.data.rows)) ? wl.data.rows : [];
    const so = await signedRequest(creds, {
      method: 'GET', path: '/spot/orders', query: '', body: null }, route);
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
        const pr = await phemexProducts(route);
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
        const rs = await signedRequest(creds, {
          method: 'GET', path: '/spot/orders',
          query: 'symbol=' + encodeURIComponent(sym), body: null }, route);
        if (rs.ok) { got = true; spotRows = spotRows.concat((rs.data && rs.data.rows) || (Array.isArray(rs.data) ? rs.data : [])); }
      }
      if (!got) partialErrors.push({ scope: 'spot', message: so.message || 'spot orders unavailable' });
    } else return so;
    let curScales = {}, spotBaseScales = {};
    try {
      const pr = await phemexProducts(route);
      curScales = pr.curScales || {};
      for (const s in (pr.spot || {})) spotBaseScales[s] = pr.spot[s].value_scale;
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

  // Bitget native account read (#1716): signed GETs mirroring BitgetAdapter's
  // state seed. Spot + futures are SEPARATE accounts (no unified pool).
  // Futures sizes are plain BASE coin (no multiplier). Fail-closed per leg.
  async function execBitgetAcctRead(intent) {
    const creds = credsGet(intent.credSlot || 'bitget');
    if (!creds) return { ok: false, message: 'No API key on this device — provision Native trading first' };
    if (!creds.pass) return { ok: false, message: 'Bitget API passphrase missing — re-provision Native trading on this device' };
    const route = routeNorm(intent.route);
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
    return { ok: true,
             spotAssets: dl(spotAssets), futAccounts: dl(futAcc), positions: dl(pos),
             futOrders: fo.rows, planOrders: plans, spotOrders: so.rows };
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
    return { ok: true,
             spotAccounts: ((spotAcc.data || {}).data) || [],
             futOverview: (overview.data || {}).data || null,
             positions: ((pos.data || {}).data) || [],
             futOrders: fo.rows, stopOrders: stops.rows, spotOrders: so.rows };
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
          (o) => !krTombHit(sess.fut.tombs, String((o || {}).order_id || ''), tnowF));
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
      const bal = await krRequest(creds, 'POST', 'spot', '/0/private/BalanceEx', null, route);
      if (!bal.ok) return bal;
      const so = await krRequest(creds, 'POST', 'spot', '/0/private/OpenOrders', null, route);
      if (!so.ok) return so;
      // Flatten the spot OpenOrders map to [{txid, o}] preserving the ids.
      const spotOrders = [];
      const openMap = (((so.data || {}).result) || {}).open || {};
      for (const txid of Object.keys(openMap)) {
        // #1876: tombstoned (just-removed) ids never resurrect off a stale page
        if (sess && krTombHit(sess.spot.tombs, txid, Date.now())) continue;
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
                                  sess.spot.fillTouch || null, Date.now());
        sess.spot.totals = aud.totals;
        if (aud.div.length) {
          divA = aud.div.slice(0, 6);
          tdiag('acct', 'kr_audit_div', { k: slot, n: aud.div.length,
                                          a: divA.join(',').slice(0, 80) });
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
            // confirms it gone — its tombstone has done its job
            sess.spot.tombs = krTombConfirm(sess.spot.tombs, ids, soT0);
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
    const out = { ok: true, wsSpot: false, wsFut: false, spot: [], futures: [] };
    if (krPairFor(creds, 'spot')) {
      if (!krFillsScopeReady(sess && krWsLive(sess.spot), sess && sess.spot.fills)) {
        return { ok: false, message: (sess && (sess.spot.err || sess.fut.err))
                                     || 'Kraken spot fills not seeded yet' };
      }
      out.wsSpot = true;
      out.spot = krFillsWindow(sess.spot.fills, start, end);
    }
    if (krPairFor(creds, 'futures')) {
      if (!krFillsScopeReady(sess && krWsLive(sess.fut), sess && sess.fut.fills)) {
        return { ok: false, message: (sess && (sess.fut.err || sess.spot.err))
                                     || 'Kraken futures fills not seeded yet' };
      }
      out.wsFut = true;
      out.futures = krFillsWindow(sess.fut.fills, start, end);
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
    if (market !== 'futures' && krPairFor(creds, 'spot')) {
      let codeMap = {};
      try { codeMap = ((await krProducts(route)) || {}).spotCode || {}; } catch (e) {}
      let ofs = 0;
      for (let page = 0; page < HB_KR_MAX_PAGES && ofs !== null; page++) {
        if (page) await new Promise((rs) => setTimeout(rs, HB_PAGE_GAP_MS));
        const th = await krRequest(creds, 'POST', 'spot', '/0/private/TradesHistory',
          [['start', String(w.frm / 1000)], ['end', String(w.to / 1000)],
           // #1829: per-execution rows only — never the consolidated synthetic.
           ['ofs', String(ofs)], ['consolidate_taker', 'false']], route);
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
    'kraken|spot':    { host: 'api.kraken.com',     base: '', prefixes: ['/0/public/AssetPairs', '/0/public/OHLC'], hdrs: CAT_BROWSER_HDRS },
    'kraken|futures': { host: 'futures.kraken.com', base: '', prefixes: ['/derivatives/api/v3/instruments', '/api/charts/v1/trade/'], hdrs: CAT_BROWSER_HDRS },
    // Arcus futures host also carries the SPOT catalog overview (hostMarket
    // quirk) → its prefix list includes /v1/api-meta/spot/overview.
    'arcus|futures':  { host: 'api.arcus.xyz',            base: '', prefixes: ['/v1/markets', '/v1/candles', '/v1/api-meta/spot/overview'] },
    'arcus|spot':     { host: 'indexer.spot.arcus.xyz',   base: '', prefixes: ['/token-candles/'] },
  };
  // 8MB cap: full venue catalogs (KuCoin symbols, MEXC exchangeInfo, etc.)
  // routinely exceed httpJson's 256KB default — a truncated body would fail
  // the panel parser (see .agents/memory/shell-httpjson-response-cap.md).
  const CAT_GET_MAXBYTES = 8 * 1024 * 1024;
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
    try {
      // Catalogs can be huge (full product lists) — same 8 MB cap as the
      // Phemex products fetch; httpJson's default 256 KB would truncate.
      const r = await httpJson(u.hostname, method, u.pathname, u.search.replace(/^\?/, ''),
                               body, {}, route, 8 * 1024 * 1024);
      return { ok: true, status: r.status | 0, body: r.text || '' };
    } catch (e) {
      const em = (e && e.message) || 'error';
      if (em === 'proxy-unavailable') return { ok: false, message: 'Proxy is enabled but unavailable' };
      return { ok: false, message: 'catalog fetch failed: ' + em };
    }
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
      // Non-2xx still returns ok:true with the status so the panel can treat
      // the reply like a fetch Response (new Response(text, {status})). The
      // RAW body text goes back untouched — the panel parser owns the shape.
      return { ok: true, status: (r && r.status) || 0, text: (r && r.text) || '' };
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
    // #1844 own-trade history backfill (re-import source) — kraken/phemex
    // raw rows for the panel to POST to /history/reimport. Old shells fall
    // through to 'unknown op'; the panel then offers the server-key path.
    if (intent && typeof intent === 'object' && intent.op === 'history_backfill') {
      return await execHistoryBackfill(intent);
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
      if (intent.venue === 'bybit') return await execBybit(creds, intent, route);
      if (intent.venue === 'okx') return await execOkx(creds, intent, route);
      if (intent.venue === 'gate') return await execGate(creds, intent, route);
      if (intent.venue === 'bitget') return await execBitget(creds, intent, route);
      if (intent.venue === 'kucoin') return await execKucoin(creds, intent, route);
      if (intent.venue === 'bitmex') return await execBitmex(creds, intent, route);
      if (intent.venue === 'mexc') return await execMexc(creds, intent, route);
      if (intent.venue === 'hyperliquid') return await execHyperliquid(creds, intent, route);
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
    return r;
  });

  return { execIntent, credsStatus };   // exposed for shell-internal use/tests
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
  krAuditGate,
  // pure — #1876 gone-order tombstones (no badge resurrection)
  KR_TOMB_TTL_MS,
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
  krFillsCachePush,
  krFillsWindow,
  krFillsScopeReady,
  // pure — Kraken private-WS lag recorder (#1835)
  krLagNew,
  krLagRec,
  krLagPct,
  krLagSnap,
  // pure — acct_read rate-limit guard (#1724)
  ACCT_RL_COOLDOWN_MS,
  ACCT_READ_MEMO_MS,
  acctRlHit,
  acctRlWaitMs,
  acctReadGuard,
  // runtime
  createTradeNative,
};
