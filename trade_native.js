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
const { routeNorm } = require('./route_hosts');
const dexSign = require('./dex_sign.js');

let SocksProxyAgent = null, HttpsProxyAgent = null;
try { SocksProxyAgent = require('socks-proxy-agent').SocksProxyAgent; } catch (e) { /* optional */ }
try { HttpsProxyAgent = require('https-proxy-agent').HttpsProxyAgent; } catch (e) { /* optional */ }

const PHEMEX_BASE = 'https://api.phemex.com';
const PHEMEX_HOST = 'api.phemex.com';
const PHEMEX_EXPIRY_S = 60;
const HTTP_TIMEOUT_MS = 12000;
const PRODUCTS_TTL_MS = 10 * 60 * 1000;
const TIMESYNC_TTL_MS = 10 * 60 * 1000;

// Venues this module can trade natively. The registry keys everything
// (validation, signer pick, creds slots) so adding a venue is additive.
const TRADE_VENUES = ['phemex', 'binance', 'bybit', 'okx', 'gate', 'bitget', 'kucoin', 'bitmex',
                      'hyperliquid', 'asterdex', 'arcus'];
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
  if (['order', 'cancel', 'cancel_all', 'close', 'sltp'].indexOf(it.op) < 0) return 'unknown op';
  const market = it.market;
  if (it.op !== 'close' && it.op !== 'sltp' && market !== 'spot' && market !== 'futures') {
    return 'market must be spot or futures';
  }
  const sym = it.symbol;
  const symRe = DEX_VENUES.indexOf(it.venue) >= 0
    ? /^[A-Za-z0-9._:/@-]+$/ : /^[A-Za-z0-9._-]+$/;
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
  if (it.op === 'sltp') {
    if (it.kind !== 'sl' && it.kind !== 'tp') return 'bad kind';
    if (!posDecOk(it.trigger)) return 'bad trigger';
    if (typeof it.clOrdID !== 'string' || !it.clOrdID || it.clOrdID.length > 64) return 'bad clOrdID';
  }
  return null;
}

// SL/TP trigger sanity vs the position side + mark (parity with the engine's
// sltp_trigger_ok): SL sits on the LOSS side of mark, TP on the PROFIT side.
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
                        '404000', '100004']) {
    if (s.indexOf(needle) >= 0) return true;
  }
  return false;
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
// Runtime wiring (electron main). Everything below touches the network /
// disk / IPC and is exercised only inside the shell.
// ---------------------------------------------------------------------------
function createTradeNative(opts) {
  const ipcMain = opts.ipcMain;
  const safeStorage = opts.safeStorage;
  const getProxyConfig = opts.getProxyConfig;
  const senderOk = opts.senderOk;              // top-level app-origin frame gate
  const userDataDir = opts.userDataDir;        // function → app.getPath('userData')

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
    if (!key || !secret || key.length > 200 || secret.length > 500) {
      return { ok: false, error: 'bad-creds' };
    }
    const payload = { key: key, secret: secret };
    if (creds.passphrase) payload.pass = String(creds.passphrase).slice(0, 200);
    let b64;
    try {
      b64 = safeStorage.encryptString(JSON.stringify(payload)).toString('base64');
    } catch (e) { return { ok: false, error: 'encrypt-failed' }; }
    const venues = credsLoadAll();
    venues[venue] = { b64: b64, tail: key.length >= 4 ? key.slice(-4) : key, ts: Math.floor(Date.now() / 1000) };
    if (!credsSaveAll(venues)) return { ok: false, error: 'persist-failed' };
    return { ok: true, tail: venues[venue].tail };
  }
  function credsWipe(venue) {
    const venues = credsLoadAll();
    if (venue) delete venues[venue];
    credsSaveAll(venues);
    return { ok: true };
  }
  function credsStatus() {
    const venues = credsLoadAll();
    const out = {};
    for (const v of TRADE_VENUES) {
      const r = venues[v];
      out[v] = r && r.b64 ? { present: true, tail: r.tail || '', ts: r.ts || 0 } : { present: false };
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
    try {
      if (cfg.scheme === 'socks5' && SocksProxyAgent) return { agent: new SocksProxyAgent(proxyUrl) };
      if (cfg.scheme === 'http' && HttpsProxyAgent) return { agent: new HttpsProxyAgent(proxyUrl) };
    } catch (e) { /* fall through */ }
    return { refuse: true };   // never dial direct past an enabled proxy
  }

  function httpJson(host, method, reqPath, query, bodyStr, headers, route) {
    return new Promise((resolve, reject) => {
      const ag = agentFor(route);
      if (ag.refuse) { reject(new Error('proxy-unavailable')); return; }
      const h = Object.assign({}, headers);
      if (bodyStr) h['Content-Type'] = 'application/json';
      h['Content-Length'] = Buffer.byteLength(bodyStr || '');
      const req = https.request({
        host: host, method: method,
        path: reqPath + (query ? '?' + query : ''),
        agent: ag.agent, headers: h, timeout: HTTP_TIMEOUT_MS,
      }, (res) => {
        let buf = '';
        res.setEncoding('utf8');
        res.on('data', (d) => { if (buf.length < 262144) buf += d; });
        res.on('end', () => resolve({ status: res.statusCode, text: buf }));
      });
      req.on('timeout', () => { try { req.destroy(new Error('timeout')); } catch (e) { /* noop */ } });
      req.on('error', reject);
      req.end(bodyStr || '');
    });
  }

  // --- venue time sync (offset refreshed lazily; failure → offset 0) -------
  const timeSync = { offsetSec: 0, ts: 0 };
  async function ensureTimeSync(route) {
    if (Date.now() - timeSync.ts < TIMESYNC_TTL_MS) return;
    timeSync.ts = Date.now();          // stamp first — one probe per TTL even on failure
    try {
      const t0 = Date.now();
      const r = await httpJson(PHEMEX_HOST, 'GET', '/public/time', '', null, {}, route);
      const d = JSON.parse(r.text);
      const st = Number(d && d.data && (d.data.serverTime || d.data.timestamp));
      if (isFinite(st) && st > 1e12) {
        const mid = (t0 + Date.now()) / 2;
        timeSync.offsetSec = (st - mid) / 1000;
      }
    } catch (e) { /* keep last offset (0 initially — engine-parity behavior) */ }
  }

  // --- products cache (spot base valueScale) -------------------------------
  const products = { spot: null, ts: 0 };
  async function spotSpec(symbol, route) {
    if (!products.spot || Date.now() - products.ts > PRODUCTS_TTL_MS) {
      const r = await httpJson(PHEMEX_HOST, 'GET', '/public/products', '', null, {}, route);
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
        spot[p.symbol] = { value_scale: Number.isInteger(vs) ? vs : 8 };
      }
      products.spot = spot;
      products.ts = Date.now();
    }
    return products.spot[symbol] || null;
  }

  // --- signed request runner ------------------------------------------------
  async function signedRequest(creds, step, route) {
    await ensureTimeSync(route);
    const bodyStr = step.body != null ? canonJson(step.body) : '';
    const expiry = phemexExpiry(null, timeSync.offsetSec);
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
      return { ok: false, message: phemexErrorMessage(code, String((data && data.msg) || '')) };
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

  async function bnRequest(creds, method, market, reqPath, params, route) {
    const q = formEnc((params || []).concat([
      ['recvWindow', String(BINANCE_RECV_WINDOW_MS)],
      ['timestamp', String(Date.now())],
    ]));
    const query = q + '&signature=' + binanceSign(creds.secret, q);
    let r;
    try {
      r = await httpJson(bnHost(market), method, reqPath, query, null,
                         { 'X-MBX-APIKEY': creds.key }, route);
    } catch (e) { return transportFail(e, 'Binance'); }
    if (r.status === 429 || r.status === 418) {
      return { ok: false, message: 'Rate limited by Binance — retry shortly', code: null };
    }
    let data = null;
    try { data = JSON.parse(r.text); } catch (e) { data = null; }
    const code = (data && typeof data.code === 'number') ? data.code : null;
    if (r.status >= 400 || (code != null && code < 0)) {
      const msg = code != null ? binanceErrorMessage(code, String((data && data.msg) || ''))
                               : 'Binance returned HTTP ' + r.status;
      return { ok: false, message: msg, code: code };
    }
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
      const r = await bnRequest(creds, 'GET', 'futures', '/fapi/v2/positionRisk', [], route);
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
    const ts = String(Date.now());
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
    const ts = okxTs();
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
    const ts = String(Math.floor(Date.now() / 1000));
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
    const ts = String(Date.now());
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
    const ts = String(Date.now());
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
    if (r.status === 429) return { ok: false, message: 'Rate limited by KuCoin — retry shortly' };
    let data;
    try { data = r.text ? JSON.parse(r.text) : {}; } catch (e) {
      return { ok: false, message: 'KuCoin returned HTTP ' + r.status };
    }
    const code = (data && typeof data === 'object' && data.code != null) ? String(data.code) : null;
    if (code == null) {
      if (r.status >= 400) return { ok: false, message: 'KuCoin returned HTTP ' + r.status };
      return { ok: true, data: data };
    }
    if (code === '200000') return { ok: true, data: data };
    return { ok: false, message: kcErrorMessage(code, String((data && data.msg) || '')) };
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
        // Sweep untriggered stops too — terminal rule.
        const pend = [];
        for (let page = 1; page <= 10; page++) {
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
          const rc = await kcRequest(creds, 'DELETE', 'futures',
                                     '/api/v1/stopOrders/' + sid, null, null, route);
          if (!rc.ok) {
            if (kucoinCancelGone(rc.message)) continue;
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
    const expires = bmxExpires();
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
    if (r.status === 429) return { ok: false, message: 'Rate limited by BitMEX — retry shortly' };
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
      return { ok: true, cancelled: 'all' };
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
    let parts;
    try {
      parts = dexSign.asterSignParams(creds.key, creds.pass, creds.secret, params || []);
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
      const r = await asterRequest(creds, 'GET', 'futures', '/fapi/v2/positionRisk', [], route);
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

  // One intent → executed result (renderer-facing shape mirrors the engine).
  async function execIntent(intent) {
    const verr = validateIntent(intent);
    if (verr) return { ok: false, message: verr };
    const creds = credsGet(intent.venue);
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
      if (intent.venue === 'hyperliquid') return await execHyperliquid(creds, intent, route);
      if (intent.venue === 'asterdex') return await execAster(creds, intent, route);
      if (intent.venue === 'arcus') return await execArcus(creds, intent, route);
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
        const r = await signedRequest(creds, { method: 'POST', path: '/g-orders', query: '', body: body }, route);
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
        const r = await signedRequest(creds, { method: 'POST', path: '/g-orders', query: '', body: body }, route);
        if (!r.ok) return r;
        const oid = r.data && (r.data.orderID || r.data.orderId);
        return { ok: true, kind: intent.kind, orderID: oid || null, clOrdID: intent.clOrdID };
      }
      // order / cancel / cancel_all ride the pure request builders.
      let spec = null;
      if (intent.op === 'order' && intent.market === 'spot') {
        try { spec = await spotSpec(intent.symbol, route); } catch (e) { spec = null; }
        if (!spec) return { ok: false, message: 'Unknown spot symbol ' + intent.symbol };
      }
      let steps;
      try { steps = buildPhemexRequests(intent, spec); } catch (e) {
        return { ok: false, message: (e && e.message) || 'bad intent' };
      }
      let last = null;
      for (const step of steps) {
        last = await signedRequest(creds, step, route);
        if (!last.ok) return last;   // FAIL LOUD — no partial-success masking
      }
      if (intent.op === 'order') {
        const oid = last.data && (last.data.orderID || last.data.orderId);
        return { ok: true, orderID: oid || null, clOrdID: intent.clOrdID };
      }
      if (intent.op === 'cancel') return { ok: true, cancelled: intent.orderID };
      return { ok: true, cancelled: 'all' };
    } catch (e) {
      return { ok: false, message: 'Native trade failed: ' + ((e && e.message) || 'error') };
    }
  }

  // --- IPC surface -----------------------------------------------------------
  ipcMain.handle('att:trade-creds-set', (event, venue, creds) => {
    if (!senderOk(event)) return { ok: false, error: 'forbidden' };
    if (TRADE_VENUES.indexOf(venue) < 0) return { ok: false, error: 'bad-venue' };
    if (!creds || typeof creds !== 'object') return { ok: false, error: 'bad-creds' };
    return credsSet(venue, creds);
  });
  ipcMain.handle('att:trade-creds-wipe', (event, venue) => {
    if (!senderOk(event)) return { ok: false, error: 'forbidden' };
    if (TRADE_VENUES.indexOf(venue) < 0) return { ok: false, error: 'bad-venue' };
    return credsWipe(venue);
  });
  ipcMain.handle('att:trade-creds-status', (event) => {
    if (!senderOk(event)) return { ok: false, error: 'forbidden' };
    return credsStatus();
  });
  ipcMain.handle('att:trade-exec', (event, intent) => {
    if (!senderOk(event)) return { ok: false, message: 'forbidden' };
    return execIntent(intent);
  });

  return { execIntent, credsStatus };   // exposed for shell-internal use/tests
}

module.exports = {
  // pure (parity/validation tested under plain node)
  PHEMEX_BASE,
  TRADE_VENUES,
  decParts,
  futReal,
  spotToScaled,
  phemexSign,
  phemexExpiry,
  phemexFuturesOrderBody,
  phemexSpotOrderBody,
  canonJson,
  buildPhemexRequests,
  phemexPositionRows,
  findPosition,
  validateIntent,
  sltpTriggerOk,
  phemexErrorMessage,
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
  // runtime
  createTradeNative,
};
