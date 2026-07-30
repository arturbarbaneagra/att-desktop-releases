// Per-venue × per-market Proxy/Direct ROUTE for Terminal market data — the
// pure, node-testable half (no Electron imports; see tests/test_desktop_route_hosts.py).
//
// Two consumers in main.js:
//   • Native sockets get EXACT per-connection routing: the renderer passes
//     route ('proxy'|'direct') on att:ws-open / att:ws-open-kucoin and main
//     validates it with routeNorm() (anything unknown collapses to 'proxy' —
//     fail-CLOSED onto the tunnel, never silently direct).
//   • Browser sockets can only be routed per-HOST via Chromium's
//     proxyBypassRules. VENUE_ROUTE_HOSTS statically maps each venue|market
//     combo to the hosts its BROWSER path dials (WS + browser-direct REST,
//     mirrored from panel.html's constants — relay-only paths have no entry).
//     bypassHostsFor() derives the bypass list from the renderer's set of
//     direct combos with PROXY-WINS-TIES: a host shared by several combos
//     (e.g. ws.phemex.com carries spot AND futures) is bypassed only when
//     EVERY combo that dials it is direct, so flipping one market to Direct
//     never yanks the other market off the proxy.
'use strict';

// venue|market -> hostnames the BROWSER transport dials for that combo.
// KuCoin has no entry: its browser path is the same-origin server relay
// (never proxied by the desktop shell) and its native path is routed exactly
// via the route arg on att:ws-open-kucoin.
const VENUE_ROUTE_HOSTS = {
  'phemex|futures':      ['ws.phemex.com'],
  'phemex|spot':         ['ws.phemex.com'],
  'binance|futures':     ['fstream.binance.com', 'fapi.binance.com'],
  'binance|spot':        ['stream.binance.com', 'api.binance.com'],
  'binance|alpha':       ['nbstream.binance.com', 'www.binance.com'],
  'okx|futures':         ['ws.okx.com', 'www.okx.com'],
  'okx|spot':            ['ws.okx.com', 'www.okx.com'],
  'bybit|futures':       ['stream.bybit.com', 'api.bybit.com'],
  'bybit|spot':          ['stream.bybit.com', 'api.bybit.com'],
  'bitget|futures':      ['ws.bitget.com', 'api.bitget.com'],
  'bitget|spot':         ['ws.bitget.com', 'api.bitget.com'],
  'gate|futures':        ['fx-ws.gateio.ws'],
  'gate|spot':           ['api.gateio.ws'],
  'bitmex|futures':      ['ws.bitmex.com'],
  'bitmex|spot':         ['ws.bitmex.com'],
  'hyperliquid|futures': ['api.hyperliquid.xyz'],
  'hyperliquid|spot':    ['api.hyperliquid.xyz'],
  'asterdex|futures':    ['fstream.asterdex.com', 'fapi.asterdex.com'],
  'asterdex|spot':       ['sstream.asterdex.com', 'sapi.asterdex.com'],
  'arcus|futures':       ['api.arcus.xyz'],
  'arcus|spot':          ['indexer.spot.arcus.xyz'],
  'lighter|futures':     ['mainnet.zklighter.elliot.ai'],
  'lighter|spot':        ['mainnet.zklighter.elliot.ai'],
  'kucoin|futures':      [],
  'kucoin|spot':         [],
  'mexc|futures':        ['contract.mexc.com'],
  'mexc|spot':           [],
  'kraken|futures':      ['futures.kraken.com'],
  'kraken|spot':         ['ws.kraken.com'],
};

// Normalize a renderer-supplied route. ONLY the literal string 'direct' opts a
// connection off the tunnel; everything else (missing, junk, objects) is
// 'proxy' — an attacker-shaped or stale value can never widen egress.
function routeNorm(route) {
  return route === 'direct' ? 'direct' : 'proxy';
}

// Derive Chromium proxyBypassRules host entries from the renderer's list of
// DIRECT venue|market tokens. Unknown tokens are ignored (old panel builds /
// junk). Proxy wins ties: a host is bypassed only when EVERY combo mapping to
// it is in the direct set. Output is deduped + sorted (stable rules string).
function bypassHostsFor(tokens) {
  const direct = new Set();
  if (Array.isArray(tokens)) {
    for (const t of tokens) {
      if (typeof t === 'string' && Object.prototype.hasOwnProperty.call(VENUE_ROUTE_HOSTS, t)) direct.add(t);
    }
  }
  // host -> every combo that dials it
  const owners = {};
  for (const combo of Object.keys(VENUE_ROUTE_HOSTS)) {
    for (const h of VENUE_ROUTE_HOSTS[combo]) (owners[h] || (owners[h] = [])).push(combo);
  }
  const out = [];
  for (const h of Object.keys(owners)) {
    if (owners[h].every((c) => direct.has(c))) out.push(h);
  }
  out.sort();
  return out;
}

module.exports = { VENUE_ROUTE_HOSTS, routeNorm, bypassHostsFor };
