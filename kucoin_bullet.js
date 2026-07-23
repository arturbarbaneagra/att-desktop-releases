'use strict';

// Pure helpers for the KuCoin native-WS bullet dance (no Electron imports so
// they are node-unit-testable). The Electron main process POSTs
// /api/v1/bullet-public, validates the response through kcBulletParse, and
// dials the returned endpoint with ?token=…&connectId=… — mirroring exactly
// what main.py's _kc_bullet_public does for the server relay (and what
// MetaScalp does natively from the user's PC).

// The two upstream bullet hosts — the renderer only ever names a MARKET
// ('spot'|'futures'); it can never supply a host of its own.
const KC_BULLET_HOSTS = {
  spot: 'https://api.kucoin.com',
  futures: 'https://api-futures.kucoin.com',
};

// App-level keepalive cadence from the bullet's pingInterval (ms): 60% of the
// advertised interval, clamped to 5s..16s; 16s fallback when absent/garbage
// (same spirit as main.py's KUCOIN_WS_PING_FALLBACK_S — KuCoin drops a socket
// ~18s without an app-level ping; WS protocol frames don't count).
function kcPingMs(raw) {
  const n = Number(raw);
  if (!isFinite(n) || n <= 0) return 16000;
  return Math.max(5000, Math.min(16000, Math.round(n * 0.6)));
}

// Validate a bullet-public response body (string or parsed object).
// Success shape: { ok:true, endpoint, token, pingMs }.
// The endpoint host VARIES per bullet, so a fixed-host allowlist can't cover
// it — the wss-only + *.kucoin.com suffix check is what keeps the bridge from
// becoming an arbitrary-socket primitive.
function kcBulletParse(body) {
  let o = body;
  if (typeof body === 'string') {
    try { o = JSON.parse(body); } catch (e) { return { ok: false, error: 'bad-json' }; }
  }
  if (!o || String(o.code) !== '200000' || !o.data) return { ok: false, error: 'bad-code' };
  const token = String(o.data.token || '');
  const srv = Array.isArray(o.data.instanceServers) ? o.data.instanceServers[0] : null;
  const endpoint = srv ? String(srv.endpoint || '') : '';
  if (!token || !endpoint) return { ok: false, error: 'missing-fields' };
  let host;
  try {
    const u = new URL(endpoint);
    if (u.protocol !== 'wss:') return { ok: false, error: 'not-wss' };
    host = u.hostname;
  } catch (e) { return { ok: false, error: 'bad-endpoint' }; }
  if (!(host === 'kucoin.com' || host.endsWith('.kucoin.com'))) return { ok: false, error: 'bad-host' };
  return { ok: true, endpoint: endpoint, token: token, pingMs: kcPingMs(srv && srv.pingInterval) };
}

// Full dial URL for a validated bullet.
function kcDialUrl(endpoint, token, connectId) {
  return endpoint + (endpoint.indexOf('?') >= 0 ? '&' : '?') +
    'token=' + encodeURIComponent(token) + '&connectId=' + encodeURIComponent(connectId);
}

module.exports = { KC_BULLET_HOSTS, kcPingMs, kcBulletParse, kcDialUrl };
