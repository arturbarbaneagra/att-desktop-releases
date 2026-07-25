'use strict';
// Pure helper: build the outbound proxy-agent URL from the persisted desktop
// proxy config. For socks5 we deliberately emit `socks5h://` — socks-proxy-agent
// (same convention as curl) treats plain `socks5://` as LOCAL DNS lookup, and
// only the `h` variant resolves hostnames AT the proxy. Chromium's session
// proxyRules keep plain `socks5://` (Chromium already resolves remotely and
// does not parse `socks5h`). Keeping both stacks on remote DNS means native
// sockets behave identically to browser mode on DNS-poisoned/filtered networks.
// Returns the URL string, or null when the config is absent/disabled/unknown.
function nativeProxyUrl(cfg) {
  if (!cfg || !cfg.enabled) return null;
  if (cfg.scheme === 'socks5') return 'socks5h://' + cfg.host + ':' + cfg.port;
  if (cfg.scheme === 'http') return 'http://' + cfg.host + ':' + cfg.port;
  return null;
}

module.exports = { nativeProxyUrl };
