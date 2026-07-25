// dex_sign.js — shared client-side signing core for the wallet-key DEX venues
// (Hyperliquid / AsterDex / Arcus). ONE file, loaded by BOTH transports:
//   • Native  — required by desktop/trade_native.js (Electron main process)
//   • Browser — inlined VERBATIM into panel.html between the
//     ==DEX_SIGN_START== / ==DEX_SIGN_END== markers (a pytest asserts the
//     panel block is byte-identical to this file, DOM_PURE-style).
// Everything here is PURE and dependency-free (no require/CDN): hand-rolled
// keccak-256, sha-256(+HMAC), sha-512, md5, ed25519 (RFC 8032), secp256k1
// ECDSA (RFC 6979, low-s), a Python-msgpack-compatible encoder, the two
// fixed EIP-712 schemas the venues use, and exact-decimal helpers — all
// ported 1:1 from terminal_engine.py and pinned by Python↔JS golden-vector
// parity tests (tests/test_dex_trading_transport.py). Signatures are fully
// deterministic, so parity is byte-exact end to end.
(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.DexSign = factory();
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ── bases (mirror terminal_engine.py constants) ───────────────────────────
  var HL_API_BASE = 'https://api.hyperliquid.xyz';
  var ASTER_FUT_BASE = 'https://fapi.asterdex.com';
  var ASTER_SPOT_BASE = 'https://sapi.asterdex.com';
  var ARCUS_BASE = 'https://api.arcus.xyz';
  var HL_SPOT_ASSET_OFFSET = 10000;
  var HL_BUILDER_ASSET_BASE = 100000;
  var HL_BUILDER_ASSET_STRIDE = 10000;
  var HL_MARKET_SLIP_PCT = '0.05';     // market = IOC limit bounded ±5% of mid
  var ARCUS_MARKET_SLIP_PCT = '0.10';  // MARKET = IOC + protective ±10% of mark
  var ARCUS_GTT_DAYS = 40;             // LIMIT rests as GTT ~40d out

  // ── byte utils ──────────────────────────────────────────────────────────
  function hexToBytes(hex) {
    var h = String(hex);
    if (h.slice(0, 2) === '0x' || h.slice(0, 2) === '0X') h = h.slice(2);
    if (h.length % 2) h = '0' + h;
    var out = new Uint8Array(h.length / 2);
    for (var i = 0; i < out.length; i++) {
      var b = parseInt(h.substr(i * 2, 2), 16);
      if (isNaN(b)) throw new Error('bad hex');
      out[i] = b;
    }
    return out;
  }
  function bytesToHex(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    return s;
  }
  function utf8Bytes(str) {
    var s = String(str), out = [];
    for (var i = 0; i < s.length; i++) {
      var c = s.codePointAt(i);
      if (c > 0xffff) i++;
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
      else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
      else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return new Uint8Array(out);
  }
  function concatBytes() {
    var n = 0, i, a;
    for (i = 0; i < arguments.length; i++) n += arguments[i].length;
    var out = new Uint8Array(n), o = 0;
    for (i = 0; i < arguments.length; i++) { a = arguments[i]; out.set(a, o); o += a.length; }
    return out;
  }
  function bigToBytes(v, len) {
    var out = new Uint8Array(len), x = v;
    for (var i = len - 1; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
    if (x !== 0n) throw new Error('int too big for ' + len + ' bytes');
    return out;
  }
  function bytesToBig(bytes) {
    var v = 0n;
    for (var i = 0; i < bytes.length; i++) v = (v << 8n) | BigInt(bytes[i]);
    return v;
  }

  // ── keccak-256 (original Keccak padding 0x01, NOT SHA-3's 0x06) ──────────
  var KECCAK_RC = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n];
  var KECCAK_ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]];
  var M64 = 0xffffffffffffffffn;
  function rotl64(x, n) {
    if (!n) return x & M64;
    return ((x << BigInt(n)) | (x >> BigInt(64 - n))) & M64;
  }
  function keccakF(st) {
    var x, y, r, C = new Array(5), D = new Array(5), B = new Array(25);
    for (r = 0; r < 24; r++) {
      for (x = 0; x < 5; x++) C[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
      for (x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
      for (x = 0; x < 5; x++) for (y = 0; y < 5; y++) {
        B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(st[x + 5 * y] ^ D[x], KECCAK_ROT[x][y]);
      }
      for (x = 0; x < 5; x++) for (y = 0; y < 5; y++) {
        st[x + 5 * y] = B[x + 5 * y] ^ ((~B[((x + 1) % 5) + 5 * y]) & M64 & B[((x + 2) % 5) + 5 * y]);
      }
      st[0] ^= KECCAK_RC[r];
    }
  }
  function keccak256(bytes) {
    var st = new Array(25), i, j;
    for (i = 0; i < 25; i++) st[i] = 0n;
    var rate = 136;
    var padded = new Uint8Array((Math.floor(bytes.length / rate) + 1) * rate);
    padded.set(bytes);
    padded[bytes.length] = 0x01;
    padded[padded.length - 1] |= 0x80;
    for (i = 0; i < padded.length; i += rate) {
      for (j = 0; j < rate / 8; j++) {
        var lane = 0n;
        for (var k = 7; k >= 0; k--) lane = (lane << 8n) | BigInt(padded[i + j * 8 + k]);
        st[j] ^= lane;
      }
      keccakF(st);
    }
    var out = new Uint8Array(32);
    for (i = 0; i < 4; i++) {
      var v = st[i];
      for (j = 0; j < 8; j++) { out[i * 8 + j] = Number(v & 0xffn); v >>= 8n; }
    }
    return out;
  }

  // ── sha-256 + HMAC (RFC 6979 nonce derivation) ────────────────────────────
  var SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
  function sha256(bytes) {
    var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var bl = bytes.length, padLen = (((bl + 8) >> 6) + 1) << 6;
    var msg = new Uint8Array(padLen);
    msg.set(bytes);
    msg[bl] = 0x80;
    var bits = bl * 8;
    for (var i = 0; i < 8; i++) msg[padLen - 1 - i] = (bits / Math.pow(2, 8 * i)) & 0xff;
    var w = new Array(64);
    for (var off = 0; off < padLen; off += 64) {
      var i2;
      for (i2 = 0; i2 < 16; i2++) {
        w[i2] = ((msg[off + i2 * 4] << 24) | (msg[off + i2 * 4 + 1] << 16) |
                 (msg[off + i2 * 4 + 2] << 8) | msg[off + i2 * 4 + 3]) >>> 0;
      }
      for (i2 = 16; i2 < 64; i2++) {
        var s0 = (rotr32(w[i2 - 15], 7) ^ rotr32(w[i2 - 15], 18) ^ (w[i2 - 15] >>> 3)) >>> 0;
        var s1 = (rotr32(w[i2 - 2], 17) ^ rotr32(w[i2 - 2], 19) ^ (w[i2 - 2] >>> 10)) >>> 0;
        w[i2] = (w[i2 - 16] + s0 + w[i2 - 7] + s1) >>> 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (i2 = 0; i2 < 64; i2++) {
        var S1 = (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) >>> 0;
        var ch = ((e & f) ^ (~e & g)) >>> 0;
        var t1 = (hh + S1 + ch + SHA256_K[i2] + w[i2]) >>> 0;
        var S0 = (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) >>> 0;
        var mj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
        var t2 = (S0 + mj) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
      h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
    }
    var out = new Uint8Array(32);
    for (var i3 = 0; i3 < 8; i3++) {
      out[i3 * 4] = h[i3] >>> 24; out[i3 * 4 + 1] = (h[i3] >>> 16) & 0xff;
      out[i3 * 4 + 2] = (h[i3] >>> 8) & 0xff; out[i3 * 4 + 3] = h[i3] & 0xff;
    }
    return out;
  }
  function rotr32(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }
  function hmacSha256(key, msg) {
    var k = key.length > 64 ? sha256(key) : key;
    var ipad = new Uint8Array(64), opad = new Uint8Array(64);
    for (var i = 0; i < 64; i++) {
      var b = i < k.length ? k[i] : 0;
      ipad[i] = b ^ 0x36; opad[i] = b ^ 0x5c;
    }
    return sha256(concatBytes(opad, sha256(concatBytes(ipad, msg))));
  }

  // ── sha-512 (ed25519) — BigInt 64-bit lanes ───────────────────────────────
  var SHA512_K = [
    '428a2f98d728ae22', '7137449123ef65cd', 'b5c0fbcfec4d3b2f', 'e9b5dba58189dbbc',
    '3956c25bf348b538', '59f111f1b605d019', '923f82a4af194f9b', 'ab1c5ed5da6d8118',
    'd807aa98a3030242', '12835b0145706fbe', '243185be4ee4b28c', '550c7dc3d5ffb4e2',
    '72be5d74f27b896f', '80deb1fe3b1696b1', '9bdc06a725c71235', 'c19bf174cf692694',
    'e49b69c19ef14ad2', 'efbe4786384f25e3', '0fc19dc68b8cd5b5', '240ca1cc77ac9c65',
    '2de92c6f592b0275', '4a7484aa6ea6e483', '5cb0a9dcbd41fbd4', '76f988da831153b5',
    '983e5152ee66dfab', 'a831c66d2db43210', 'b00327c898fb213f', 'bf597fc7beef0ee4',
    'c6e00bf33da88fc2', 'd5a79147930aa725', '06ca6351e003826f', '142929670a0e6e70',
    '27b70a8546d22ffc', '2e1b21385c26c926', '4d2c6dfc5ac42aed', '53380d139d95b3df',
    '650a73548baf63de', '766a0abb3c77b2a8', '81c2c92e47edaee6', '92722c851482353b',
    'a2bfe8a14cf10364', 'a81a664bbc423001', 'c24b8b70d0f89791', 'c76c51a30654be30',
    'd192e819d6ef5218', 'd69906245565a910', 'f40e35855771202a', '106aa07032bbd1b8',
    '19a4c116b8d2d0c8', '1e376c085141ab53', '2748774cdf8eeb99', '34b0bcb5e19b48a8',
    '391c0cb3c5c95a63', '4ed8aa4ae3418acb', '5b9cca4f7763e373', '682e6ff3d6b2b8a3',
    '748f82ee5defb2fc', '78a5636f43172f60', '84c87814a1f0ab72', '8cc702081a6439ec',
    '90befffa23631e28', 'a4506cebde82bde9', 'bef9a3f7b2c67915', 'c67178f2e372532b',
    'ca273eceea26619c', 'd186b8c721c0c207', 'eada7dd6cde0eb1e', 'f57d4f7fee6ed178',
    '06f067aa72176fba', '0a637dc5a2c898a6', '113f9804bef90dae', '1b710b35131c471b',
    '28db77f523047d84', '32caab7b40c72493', '3c9ebe0a15c9bebc', '431d67c49c100d4c',
    '4cc5d4becb3e42b6', '597f299cfc657e2a', '5fcb6fab3ad6faec', '6c44198c4a475817'
  ].map(function (s) { return BigInt('0x' + s); });
  function rotr64(x, n) { return ((x >> BigInt(n)) | (x << BigInt(64 - n))) & M64; }
  function sha512(bytes) {
    var h = ['6a09e667f3bcc908', 'bb67ae8584caa73b', '3c6ef372fe94f82b', 'a54ff53a5f1d36f1',
             '510e527fade682d1', '9b05688c2b3e6c1f', '1f83d9abfb41bd6b', '5be0cd19137e2179']
      .map(function (s) { return BigInt('0x' + s); });
    var bl = bytes.length, padLen = (((bl + 16) >> 7) + 1) << 7;
    var msg = new Uint8Array(padLen);
    msg.set(bytes);
    msg[bl] = 0x80;
    var bits = BigInt(bl) * 8n;
    for (var i = 0; i < 16; i++) msg[padLen - 1 - i] = Number((bits >> BigInt(8 * i)) & 0xffn);
    var w = new Array(80);
    for (var off = 0; off < padLen; off += 128) {
      var i2;
      for (i2 = 0; i2 < 16; i2++) {
        var lane = 0n;
        for (var j = 0; j < 8; j++) lane = (lane << 8n) | BigInt(msg[off + i2 * 8 + j]);
        w[i2] = lane;
      }
      for (i2 = 16; i2 < 80; i2++) {
        var s0 = rotr64(w[i2 - 15], 1) ^ rotr64(w[i2 - 15], 8) ^ (w[i2 - 15] >> 7n);
        var s1 = rotr64(w[i2 - 2], 19) ^ rotr64(w[i2 - 2], 61) ^ (w[i2 - 2] >> 6n);
        w[i2] = (w[i2 - 16] + s0 + w[i2 - 7] + s1) & M64;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (i2 = 0; i2 < 80; i2++) {
        var S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        var ch = (e & f) ^ ((~e) & M64 & g);
        var t1 = (hh + S1 + ch + SHA512_K[i2] + w[i2]) & M64;
        var S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        var mj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + mj) & M64;
        hh = g; g = f; f = e; e = (d + t1) & M64;
        d = c; c = b; b = a; a = (t1 + t2) & M64;
      }
      h[0] = (h[0] + a) & M64; h[1] = (h[1] + b) & M64; h[2] = (h[2] + c) & M64; h[3] = (h[3] + d) & M64;
      h[4] = (h[4] + e) & M64; h[5] = (h[5] + f) & M64; h[6] = (h[6] + g) & M64; h[7] = (h[7] + hh) & M64;
    }
    var out = new Uint8Array(64);
    for (var i3 = 0; i3 < 8; i3++) {
      var v = h[i3];
      for (var j2 = 7; j2 >= 0; j2--) { out[i3 * 8 + j2] = Number(v & 0xffn); v >>= 8n; }
    }
    return out;
  }

  // ── md5 (hl_cloid parity — NOT a security primitive here) ────────────────
  var MD5_S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
               5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
               4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
               6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  var MD5_K = (function () {
    var k = new Array(64);
    for (var i = 0; i < 64; i++) k[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0;
    return k;
  }());
  function md5(bytes) {
    var bl = bytes.length, padLen = (((bl + 8) >> 6) + 1) << 6;
    var msg = new Uint8Array(padLen);
    msg.set(bytes);
    msg[bl] = 0x80;
    var bits = bl * 8;
    for (var i = 0; i < 8; i++) msg[padLen - 8 + i] = (bits / Math.pow(2, 8 * i)) & 0xff;
    var a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    for (var off = 0; off < padLen; off += 64) {
      var m = new Array(16);
      for (var j = 0; j < 16; j++) {
        m[j] = (msg[off + j * 4] | (msg[off + j * 4 + 1] << 8) |
                (msg[off + j * 4 + 2] << 16) | (msg[off + j * 4 + 3] << 24)) >>> 0;
      }
      var A = a0, B = b0, C = c0, D = d0;
      for (var i2 = 0; i2 < 64; i2++) {
        var F, g;
        if (i2 < 16) { F = (B & C) | (~B & D); g = i2; }
        else if (i2 < 32) { F = (D & B) | (~D & C); g = (5 * i2 + 1) % 16; }
        else if (i2 < 48) { F = B ^ C ^ D; g = (3 * i2 + 5) % 16; }
        else { F = C ^ (B | ~D); g = (7 * i2) % 16; }
        F = (F + A + MD5_K[i2] + m[g]) >>> 0;
        A = D; D = C; C = B;
        B = (B + (((F << MD5_S[i2]) | (F >>> (32 - MD5_S[i2]))) >>> 0)) >>> 0;
      }
      a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
    }
    var out = new Uint8Array(16), regs = [a0, b0, c0, d0];
    for (var r = 0; r < 4; r++) for (var j2 = 0; j2 < 4; j2++) out[r * 4 + j2] = (regs[r] >>> (8 * j2)) & 0xff;
    return out;
  }

  // ── modular arithmetic (BigInt) ──────────────────────────────────────────
  function mod(a, m) { var r = a % m; return r < 0n ? r + m : r; }
  function powMod(base, exp, m) {
    var b = mod(base, m), e = exp, r = 1n;
    while (e > 0n) {
      if (e & 1n) r = (r * b) % m;
      b = (b * b) % m;
      e >>= 1n;
    }
    return r;
  }
  function invMod(a, m) { return powMod(mod(a, m), m - 2n, m); }  // m prime

  // ── ed25519 (RFC 8032) — Arcus signing ───────────────────────────────────
  var ED_P = (1n << 255n) - 19n;
  var ED_L = (1n << 252n) + 27742317777372353535851937790883648493n;
  var ED_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
  var ED_B = [15112221349535400772501151409588531511454012693041857206046113283949847762202n,
              46316835694926478169428394003475163141307993866256225615783033603165251855960n];
  // extended coords (X, Y, Z, T)
  function edAdd(p, q) {
    var A = mod((p[1] - p[0]) * (q[1] - q[0]), ED_P);
    var B = mod((p[1] + p[0]) * (q[1] + q[0]), ED_P);
    var C = mod(2n * p[3] * q[3] * ED_D, ED_P);
    var D = mod(2n * p[2] * q[2], ED_P);
    var E = B - A, F = D - C, G = D + C, H = B + A;
    return [mod(E * F, ED_P), mod(G * H, ED_P), mod(F * G, ED_P), mod(E * H, ED_P)];
  }
  function edMul(s, p) {
    var q = [0n, 1n, 1n, 0n], b = p, e = s;
    while (e > 0n) {
      if (e & 1n) q = edAdd(q, b);
      b = edAdd(b, b);
      e >>= 1n;
    }
    return q;
  }
  function edBasePoint() {
    return [ED_B[0], ED_B[1], 1n, mod(ED_B[0] * ED_B[1], ED_P)];
  }
  function edEncode(p) {
    var zi = invMod(p[2], ED_P);
    var x = mod(p[0] * zi, ED_P), y = mod(p[1] * zi, ED_P);
    var enc = y | ((x & 1n) << 255n);
    var out = new Uint8Array(32);
    for (var i = 0; i < 32; i++) { out[i] = Number(enc & 0xffn); enc >>= 8n; }
    return out;
  }
  function edClampScalar(h) {
    var s = 0n;
    for (var i = 31; i >= 0; i--) s = (s << 8n) | BigInt(h[i]);
    s &= (1n << 254n) - 8n;
    s |= 1n << 254n;
    return s;
  }
  function edLeBig(bytes) {
    var v = 0n;
    for (var i = bytes.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
    return v;
  }
  function edPubkeyBytes(seedHex) {
    var seed = hexToBytes(seedHex);
    if (seed.length !== 32) throw new Error('ed25519 seed must be 32 bytes');
    var h = sha512(seed);
    return edEncode(edMul(edClampScalar(h.slice(0, 32)), edBasePoint()));
  }
  function edSignHex(seedHex, msgBytes) {
    var seed = hexToBytes(seedHex);
    if (seed.length !== 32) throw new Error('ed25519 seed must be 32 bytes');
    var h = sha512(seed);
    var s = edClampScalar(h.slice(0, 32));
    var prefix = h.slice(32);
    var A = edEncode(edMul(s, edBasePoint()));
    var r = mod(edLeBig(sha512(concatBytes(prefix, msgBytes))), ED_L);
    var R = edEncode(edMul(r, edBasePoint()));
    var k = mod(edLeBig(sha512(concatBytes(R, A, msgBytes))), ED_L);
    var S = mod(r + k * s, ED_L);
    var Sb = new Uint8Array(32), v = S;
    for (var i = 0; i < 32; i++) { Sb[i] = Number(v & 0xffn); v >>= 8n; }
    return bytesToHex(concatBytes(R, Sb));
  }

  // ── secp256k1 ECDSA (RFC 6979 deterministic, low-s) — HL + Aster ─────────
  var SEC_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
  var SEC_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  var SEC_G = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
               0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n];
  // Jacobian point ops
  function jDouble(p) {
    if (p[1] === 0n) return [0n, 0n, 0n];
    var ysq = mod(p[1] * p[1], SEC_P);
    var S = mod(4n * p[0] * ysq, SEC_P);
    var Mm = mod(3n * p[0] * p[0], SEC_P);
    var nx = mod(Mm * Mm - 2n * S, SEC_P);
    var ny = mod(Mm * (S - nx) - 8n * ysq * ysq, SEC_P);
    var nz = mod(2n * p[1] * p[2], SEC_P);
    return [nx, ny, nz];
  }
  function jAdd(p, q) {
    if (p[2] === 0n) return q;
    if (q[2] === 0n) return p;
    var z1z1 = mod(p[2] * p[2], SEC_P), z2z2 = mod(q[2] * q[2], SEC_P);
    var u1 = mod(p[0] * z2z2, SEC_P), u2 = mod(q[0] * z1z1, SEC_P);
    var s1 = mod(p[1] * q[2] * z2z2, SEC_P), s2 = mod(q[1] * p[2] * z1z1, SEC_P);
    if (u1 === u2) {
      if (s1 !== s2) return [0n, 0n, 0n];
      return jDouble(p);
    }
    var H = mod(u2 - u1, SEC_P), R = mod(s2 - s1, SEC_P);
    var H2 = mod(H * H, SEC_P), H3 = mod(H * H2, SEC_P), U1H2 = mod(u1 * H2, SEC_P);
    var nx = mod(R * R - H3 - 2n * U1H2, SEC_P);
    var ny = mod(R * (U1H2 - nx) - s1 * H3, SEC_P);
    var nz = mod(H * p[2] * q[2], SEC_P);
    return [nx, ny, nz];
  }
  function jMulG(k) {
    var q = [0n, 0n, 0n], b = [SEC_G[0], SEC_G[1], 1n], e = k;
    while (e > 0n) {
      if (e & 1n) q = jAdd(q, b);
      b = jDouble(b);
      e >>= 1n;
    }
    return q;
  }
  function jAffine(p) {
    if (p[2] === 0n) throw new Error('point at infinity');
    var zi = invMod(p[2], SEC_P), zi2 = mod(zi * zi, SEC_P);
    return [mod(p[0] * zi2, SEC_P), mod(p[1] * zi2 * zi, SEC_P)];
  }
  function rfc6979K(privBytes, digest) {
    var k = new Uint8Array(32), v = new Uint8Array(32);
    var i;
    for (i = 0; i < 32; i++) { k[i] = 0; v[i] = 1; }
    var z = mod(bytesToBig(digest), SEC_N);
    var bx = concatBytes(privBytes, bigToBytes(z, 32));
    k = hmacSha256(k, concatBytes(v, new Uint8Array([0]), bx));
    v = hmacSha256(k, v);
    k = hmacSha256(k, concatBytes(v, new Uint8Array([1]), bx));
    v = hmacSha256(k, v);
    for (;;) {
      v = hmacSha256(k, v);
      var cand = bytesToBig(v);
      if (cand >= 1n && cand < SEC_N) return cand;
      k = hmacSha256(k, concatBytes(v, new Uint8Array([0])));
      v = hmacSha256(k, v);
    }
  }
  // digest (32B) + priv hex → { r, s, recid } with low-s normalization
  function secpSignDigest(privHex, digest) {
    var priv = hexToBytes(privHex);
    if (priv.length !== 32) throw new Error('secp256k1 key must be 32 bytes');
    var d = bytesToBig(priv);
    if (d <= 0n || d >= SEC_N) throw new Error('bad private key');
    var z = mod(bytesToBig(digest), SEC_N);
    var k = rfc6979K(priv, digest);
    for (;;) {
      var P = jAffine(jMulG(k));
      var r = mod(P[0], SEC_N);
      if (r === 0n) { k = mod(k + 1n, SEC_N); continue; }
      var s = mod(invMod(k, SEC_N) * mod(z + r * d, SEC_N), SEC_N);
      if (s === 0n) { k = mod(k + 1n, SEC_N); continue; }
      var recid = Number(P[1] & 1n);
      if (P[0] >= SEC_N) recid += 2;
      if (s > SEC_N >> 1n) { s = SEC_N - s; recid ^= 1; }
      return { r: r, s: s, recid: recid };
    }
  }
  function secpPubUncompressed(privHex) {
    var d = bytesToBig(hexToBytes(privHex));
    var P = jAffine(jMulG(d));
    return concatBytes(bigToBytes(P[0], 32), bigToBytes(P[1], 32));
  }

  // ── EIP-712 (the two FIXED schemas the DEX venues use) ───────────────────
  var EIP712_DOMAIN_TYPEHASH = keccak256(utf8Bytes(
    'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'));
  var EIP712_AGENT_TYPEHASH = keccak256(utf8Bytes('Agent(string source,bytes32 connectionId)'));
  var EIP712_MESSAGE_TYPEHASH = keccak256(utf8Bytes('Message(string msg)'));
  function eip712DomainSep(name, version, chainId) {
    return keccak256(concatBytes(
      EIP712_DOMAIN_TYPEHASH,
      keccak256(utf8Bytes(name)),
      keccak256(utf8Bytes(version)),
      bigToBytes(BigInt(chainId), 32),
      new Uint8Array(32)));               // verifyingContract 0x0
  }
  function eip712Digest(domainSep, structHash) {
    return keccak256(concatBytes(new Uint8Array([0x19, 0x01]), domainSep, structHash));
  }

  // ── exact-decimal helpers (Python Decimal parity, BigInt) ────────────────
  // { neg, digits (BigInt ≥ 0), scale (int ≥ 0) }
  function dxParse(v) {
    var s = String(v).trim();
    var m = /^([+-]?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(s);
    if (!m) throw new Error('bad decimal: ' + s);
    var neg = m[1] === '-';
    var frac = m[3] || '';
    var digits = BigInt(m[2] + frac);
    var scale = frac.length;
    var exp = m[4] ? parseInt(m[4], 10) : 0;
    if (exp > 0) {
      if (exp >= scale) { digits *= 10n ** BigInt(exp - scale); scale = 0; }
      else scale -= exp;
    } else if (exp < 0) {
      scale += -exp;
    }
    return { neg: neg && digits !== 0n, digits: digits, scale: scale };
  }
  function dxPow10(n) { return 10n ** BigInt(n); }
  // trimmed 'f' formatting (Decimal.normalize parity)
  function dxFmt(d) {
    if (d.digits === 0n) return '0';
    var s = d.digits.toString(), sc = d.scale;
    while (sc > 0 && s.charAt(s.length - 1) === '0') { s = s.slice(0, -1); sc -= 1; }
    if (s.length <= sc) s = new Array(sc - s.length + 2).join('0') + s;
    var out = sc > 0 ? s.slice(0, -sc) + '.' + s.slice(-sc) : s;
    return (d.neg ? '-' : '') + out;
  }
  function dxIsInt(d) { return d.scale === 0 || d.digits % dxPow10(d.scale) === 0n; }
  // Decimal.adjusted(): exponent of the most-significant digit
  function dxAdjusted(d) {
    if (d.digits === 0n) return -d.scale;
    return (d.digits.toString().length - 1) - d.scale;
  }
  // quantize to 10^exp with a rounding mode ('HALF_UP' | 'DOWN' | 'FLOOR' | 'CEILING')
  function dxQuantize(d, exp, mode) {
    var ts = -exp;                        // target scale
    if (ts >= d.scale) {
      return { neg: d.neg, digits: d.digits * dxPow10(ts - d.scale), scale: Math.max(ts, 0) < 0 ? 0 : ts < 0 ? 0 : ts };
    }
    var f = dxPow10(d.scale - ts);
    var q = d.digits / f, rem = d.digits % f;
    if (rem !== 0n) {
      if (mode === 'HALF_UP') {
        if (rem * 2n >= f) q += 1n;
      } else if (mode === 'FLOOR') {
        if (d.neg) q += 1n;
      } else if (mode === 'CEILING') {
        if (!d.neg) q += 1n;
      }                                    // 'DOWN' → truncate
    }
    if (ts < 0) { q *= dxPow10(-ts); ts = 0; }
    return { neg: d.neg && q !== 0n, digits: q, scale: ts };
  }
  function dxMulSmall(d, numer, denomScale) {
    // d × (numer / 10^denomScale) — exact
    return { neg: d.neg !== (numer < 0n), digits: d.digits * (numer < 0n ? -numer : numer),
             scale: d.scale + denomScale };
  }
  function dxCmpZero(d) { return d.digits === 0n ? 0 : (d.neg ? -1 : 1); }

  // ── Hyperliquid pure helpers (terminal_engine parity) ────────────────────
  var _hlNonceLast = 0;
  function hlNextNonce(nowMs) {
    var n = nowMs != null ? Math.floor(nowMs) : Date.now();
    if (n <= _hlNonceLast) n = _hlNonceLast + 1;
    _hlNonceLast = n;
    return n;
  }
  function hlWireNum(v) {
    var d = dxParse(v);
    if (dxIsInt(d)) d = dxQuantize(d, 0, 'DOWN');
    return dxFmt(d);
  }
  function hlPxDecimals(szDecimals, market) {
    return (market === 'spot' ? 8 : 6) - (parseInt(szDecimals, 10) || 0);
  }
  function hlRoundPx(px, szDecimals, market) {
    var d = dxParse(px);
    if (dxCmpZero(d) <= 0) throw new Error('price must be positive');
    if (!dxIsInt(d)) {
      var exp = Math.max(dxAdjusted(d) - 4, -hlPxDecimals(szDecimals, market));
      d = dxQuantize(d, exp, 'HALF_UP');
    }
    return hlWireNum(dxFmt(d));
  }
  function hlRoundSz(qty, szDecimals) {
    var d = dxQuantize(dxParse(qty), -(parseInt(szDecimals, 10) || 0), 'DOWN');
    if (dxCmpZero(d) <= 0) throw new Error('size rounds to zero');
    return hlWireNum(dxFmt(d));
  }
  // exact floor(qty / px) at szDecimals — spot market BUY sizing (USDC → base)
  function hlSizeFromQuote(quoteQty, px, szDecimals) {
    var q = dxParse(quoteQty), p = dxParse(px);
    if (dxCmpZero(p) <= 0) throw new Error('price must be positive');
    var szd = parseInt(szDecimals, 10) || 0;
    // floor(q/p × 10^szd) with exact integer math
    var num = q.digits * dxPow10(p.scale + szd);
    var den = p.digits * dxPow10(q.scale);
    var units = num / den;
    var d = { neg: false, digits: units, scale: szd };
    if (dxCmpZero(d) <= 0) throw new Error('size rounds to zero');
    return hlWireNum(dxFmt(d));
  }
  function hlCloid(clOrdID) {
    return '0x' + bytesToHex(md5(utf8Bytes(String(clOrdID))));
  }
  function hlOrderWire(asset, isBuy, px, sz, reduceOnly, tWire, cloid) {
    var w = { a: parseInt(asset, 10), b: !!isBuy, p: String(px), s: String(sz),
              r: !!reduceOnly, t: tWire };
    if (cloid) w.c = cloid;
    return w;
  }

  // msgpack encoder — Python msgpack.packb() parity (insertion-ordered maps)
  function msgpackEncode(obj) {
    var chunks = [];
    (function enc(v) {
      if (v === null || v === undefined) { chunks.push(new Uint8Array([0xc0])); return; }
      if (typeof v === 'boolean') { chunks.push(new Uint8Array([v ? 0xc3 : 0xc2])); return; }
      if (typeof v === 'bigint' || typeof v === 'number') {
        var isInt = typeof v === 'bigint' || Number.isInteger(v);
        if (!isInt) throw new Error('float in msgpack action — refuse (fail loud)');
        var n = typeof v === 'bigint' ? v : BigInt(v);
        if (n >= 0n) {
          if (n < 0x80n) chunks.push(new Uint8Array([Number(n)]));
          else if (n <= 0xffn) chunks.push(new Uint8Array([0xcc, Number(n)]));
          else if (n <= 0xffffn) chunks.push(concatBytes(new Uint8Array([0xcd]), bigToBytes(n, 2)));
          else if (n <= 0xffffffffn) chunks.push(concatBytes(new Uint8Array([0xce]), bigToBytes(n, 4)));
          else chunks.push(concatBytes(new Uint8Array([0xcf]), bigToBytes(n, 8)));
        } else {
          if (n >= -32n) chunks.push(new Uint8Array([0x100 + Number(n)]));
          else if (n >= -128n) chunks.push(new Uint8Array([0xd0, 0x100 + Number(n)]));
          else if (n >= -32768n) chunks.push(concatBytes(new Uint8Array([0xd1]), bigToBytes(n + 0x10000n, 2)));
          else if (n >= -2147483648n) chunks.push(concatBytes(new Uint8Array([0xd2]), bigToBytes(n + 0x100000000n, 4)));
          else chunks.push(concatBytes(new Uint8Array([0xd3]), bigToBytes(n + (1n << 64n), 8)));
        }
        return;
      }
      if (typeof v === 'string') {
        var b = utf8Bytes(v);
        if (b.length < 32) chunks.push(new Uint8Array([0xa0 | b.length]));
        else if (b.length <= 0xff) chunks.push(new Uint8Array([0xd9, b.length]));
        else if (b.length <= 0xffff) chunks.push(concatBytes(new Uint8Array([0xda]), bigToBytes(BigInt(b.length), 2)));
        else chunks.push(concatBytes(new Uint8Array([0xdb]), bigToBytes(BigInt(b.length), 4)));
        chunks.push(b);
        return;
      }
      if (Array.isArray(v)) {
        if (v.length < 16) chunks.push(new Uint8Array([0x90 | v.length]));
        else if (v.length <= 0xffff) chunks.push(concatBytes(new Uint8Array([0xdc]), bigToBytes(BigInt(v.length), 2)));
        else chunks.push(concatBytes(new Uint8Array([0xdd]), bigToBytes(BigInt(v.length), 4)));
        for (var i = 0; i < v.length; i++) enc(v[i]);
        return;
      }
      if (typeof v === 'object') {
        var keys = Object.keys(v);
        if (keys.length < 16) chunks.push(new Uint8Array([0x80 | keys.length]));
        else if (keys.length <= 0xffff) chunks.push(concatBytes(new Uint8Array([0xde]), bigToBytes(BigInt(keys.length), 2)));
        else chunks.push(concatBytes(new Uint8Array([0xdf]), bigToBytes(BigInt(keys.length), 4)));
        for (var j = 0; j < keys.length; j++) { enc(keys[j]); enc(v[keys[j]]); }
        return;
      }
      throw new Error('unsupported msgpack type: ' + typeof v);
    }(obj));
    return concatBytes.apply(null, chunks);
  }

  function hlActionHash(action, nonce, vaultAddress) {
    var data = msgpackEncode(action);
    data = concatBytes(data, bigToBytes(BigInt(nonce), 8));
    if (vaultAddress == null) {
      data = concatBytes(data, new Uint8Array([0]));
    } else {
      var h = String(vaultAddress);
      if (h.slice(0, 2) === '0x') h = h.slice(2);
      data = concatBytes(data, new Uint8Array([1]), hexToBytes(h));
    }
    return keccak256(data);
  }
  var HL_DOMAIN_SEP = null;   // computed lazily (keccak at module load is fine but keep cheap)
  function hlSignAction(privKey, action, nonce, vaultAddress) {
    if (!HL_DOMAIN_SEP) HL_DOMAIN_SEP = eip712DomainSep('Exchange', '1', 1337);
    var connectionId = hlActionHash(action, nonce, vaultAddress == null ? null : vaultAddress);
    var structHash = keccak256(concatBytes(
      EIP712_AGENT_TYPEHASH, keccak256(utf8Bytes('a')), connectionId));
    var digest = eip712Digest(HL_DOMAIN_SEP, structHash);
    var sig = secpSignDigest(privKey, digest);
    // eth_account parity: hex(r)/hex(s) are MINIMAL hex (no zero padding)
    return { r: '0x' + sig.r.toString(16), s: '0x' + sig.s.toString(16), v: 27 + sig.recid };
  }
  function hlSignerAddress(privKey) {
    var pub = secpPubUncompressed(privKey);
    var addr = bytesToHex(keccak256(pub).slice(12));
    // EIP-55 checksum
    var h = bytesToHex(keccak256(utf8Bytes(addr)));
    var out = '0x';
    for (var i = 0; i < 40; i++) {
      var c = addr.charAt(i);
      out += parseInt(h.charAt(i), 16) >= 8 ? c.toUpperCase() : c;
    }
    return out;
  }
  function hlCoinIsSpot(coin) {
    return String(coin).charAt(0) === '@' || String(coin).indexOf('/') >= 0;
  }
  // Pure order planner — mirrors HyperliquidAdapter.place_order. `mid` is the
  // caller-fetched allMids price (string) — required for market orders and
  // spot market BUY sizing; everything else is deterministic. Throws Error
  // with a user-readable message (fail loud, engine parity).
  function hlOrderPlan(p) {
    var spec = p.spec || {};
    var market = p.market === 'spot' ? 'spot' : 'futures';
    var szd = spec.sz_decimals || 0;
    var isBuy = String(p.side).toLowerCase() === 'buy';
    var t = String(p.ordType).toLowerCase();
    if (market === 'spot' && t !== 'limit' && t !== 'market') {
      throw new Error('Stop orders are futures-only');
    }
    var ro = !!(p.reduceOnly || p.closeOnTrigger || p.closePosition);
    var px = null, sz;
    if (market === 'spot' && t === 'market' && isBuy) {
      // Engine convention: spot market BUY qty = USDC amount.
      if (!p.mid) throw new Error('No Hyperliquid price for order sizing');
      px = hlRoundPx(dxFmt(dxMulSmall(dxParse(p.mid), 105n, 2)), szd, market);
      sz = hlSizeFromQuote(p.qty, px, szd);
    } else {
      sz = hlRoundSz(p.qty, szd);
    }
    var tWire;
    if (t === 'limit') {
      if (!p.price) throw new Error('Limit orders need a price');
      px = hlRoundPx(p.price, szd, market);
      tWire = { limit: { tif: 'Gtc' } };
    } else if (t === 'market') {
      if (px === null) {
        if (!p.mid) throw new Error('No Hyperliquid price for the market order bound');
        var bound = dxMulSmall(dxParse(p.mid), isBuy ? 105n : 95n, 2);
        px = hlRoundPx(dxFmt(bound), szd, market);
      }
      tWire = { limit: { tif: 'Ioc' } };
    } else if (t === 'stop' || t === 'stop_limit' || t === 'tp_market') {
      if (!p.trigger) throw new Error('Trigger price required');
      var trig = hlRoundPx(p.trigger, szd, market);
      var isMkt;
      if (t === 'stop_limit') {
        if (!p.price) throw new Error('Stop-limit orders need a limit price');
        px = hlRoundPx(p.price, szd, market);
        isMkt = false;
      } else {
        var bound2 = dxMulSmall(dxParse(trig), isBuy ? 105n : 95n, 2);
        px = hlRoundPx(dxFmt(bound2), szd, market);
        isMkt = true;
      }
      tWire = { trigger: { isMarket: isMkt, triggerPx: trig,
                           tpsl: t === 'tp_market' ? 'tp' : 'sl' } };
    } else {
      throw new Error('Unsupported order type: ' + p.ordType);
    }
    var wire = hlOrderWire(spec.asset, isBuy, px, sz, ro, tWire, hlCloid(p.clOrdID));
    return { action: { type: 'order', orders: [wire], grouping: 'na' },
             symbol: String(spec.symbol || p.symbol || ''), px: px, sz: sz };
  }
  function hlCancelAction(asset, orderId) {
    var oid = parseInt(String(orderId), 10);
    if (String(oid) === String(orderId).trim() && !isNaN(oid)) {
      return { type: 'cancel', cancels: [{ a: parseInt(asset, 10), o: oid }] };
    }
    var cloid = String(orderId).slice(0, 2) === '0x' ? String(orderId) : hlCloid(String(orderId));
    return { type: 'cancelByCloid', cancels: [{ asset: parseInt(asset, 10), cloid: cloid }] };
  }
  // POST /exchange answer → { ok, st|message } (hl_exchange_result parity)
  function hlExchangeResult(data) {
    if (!data || typeof data !== 'object') return { ok: false, message: 'unexpected exchange response' };
    if (data.status !== 'ok') {
      return { ok: false, message: String(data.response || data.status || 'exchange error') };
    }
    var resp = data.response || {};
    if (typeof resp !== 'object') return { ok: true, st: {} };
    var statuses = (resp.data && typeof resp.data === 'object' && resp.data.statuses) || [];
    var st = statuses.length ? statuses[0] : {};
    if (st && typeof st === 'object' && st.error) return { ok: false, message: String(st.error) };
    return { ok: true, st: (st && typeof st === 'object') ? st : {} };
  }

  // ── AsterDex pure helpers ─────────────────────────────────────────────────
  // Python urllib.parse.urlencode / quote_plus parity: unreserved chars pass,
  // space → '+', everything else %XX (uppercase hex, UTF-8 bytes).
  function urlencodePy(pairs) {
    var UNRESERVED = /[A-Za-z0-9_.\-~]/;
    function q(v) {
      var s = String(v), out = '';
      for (var i = 0; i < s.length; i++) {
        var c = s.charAt(i);
        if (UNRESERVED.test(c)) { out += c; continue; }
        if (c === ' ') { out += '+'; continue; }
        var b = utf8Bytes(c);
        for (var j = 0; j < b.length; j++) {
          out += '%' + (b[j] < 16 ? '0' : '') + b[j].toString(16).toUpperCase();
        }
      }
      return out;
    }
    var parts = [];
    for (var i2 = 0; i2 < pairs.length; i2++) parts.push(q(pairs[i2][0]) + '=' + q(pairs[i2][1]));
    return parts.join('&');
  }
  var _asterNonceLast = 0;
  function asterNextNonce(nowUs) {
    var n = nowUs != null ? Math.floor(nowUs) : Date.now() * 1000;
    if (n <= _asterNonceLast) n = _asterNonceLast + 1;
    _asterNonceLast = n;
    return n;
  }
  var ASTER_DOMAIN_SEP = null;
  // Append user+signer+nonce+EIP-712 signature (aster_sign_params parity).
  function asterSignParams(userAddr, signerAddr, privKey, params, nonce) {
    if (!ASTER_DOMAIN_SEP) ASTER_DOMAIN_SEP = eip712DomainSep('AsterSignTransaction', '1', 1666);
    var parts = [];
    for (var i = 0; i < (params || []).length; i++) parts.push([String(params[i][0]), String(params[i][1])]);
    parts.push(['user', String(userAddr)]);
    parts.push(['signer', String(signerAddr)]);
    parts.push(['nonce', String(nonce != null ? nonce : asterNextNonce())]);
    var msg = urlencodePy(parts);
    var structHash = keccak256(concatBytes(EIP712_MESSAGE_TYPEHASH, keccak256(utf8Bytes(msg))));
    var digest = eip712Digest(ASTER_DOMAIN_SEP, structHash);
    var sig = secpSignDigest(privKey, digest);
    var rHex = sig.r.toString(16), sHex = sig.s.toString(16);
    while (rHex.length < 64) rHex = '0' + rHex;
    while (sHex.length < 64) sHex = '0' + sHex;
    parts.push(['signature', '0x' + rHex + sHex + (27 + sig.recid).toString(16)]);
    return parts;
  }
  // Aster order params: Binance-family shapes on the PLAIN order endpoint —
  // Aster has NO Algo Order API, conditionals carry stopPrice/closePosition
  // (binance_order_params parity; the engine routes Aster stops the same way).
  var ASTER_TYPE_MAP = { market: 'MARKET', limit: 'LIMIT', stop: 'STOP_MARKET',
                         stop_limit: 'STOP', tp_market: 'TAKE_PROFIT_MARKET' };
  function asterOrderParams(market, symbol, side, ordType, qty, price, clOrdID, flags) {
    var f = flags || {};
    var sideU = String(side).toLowerCase() === 'buy' ? 'BUY' : 'SELL';
    var typ = ASTER_TYPE_MAP[String(ordType).toLowerCase()] || 'LIMIT';
    var params = [['symbol', String(symbol)], ['side', sideU], ['type', typ]];
    if (typ === 'LIMIT' || typ === 'STOP') {
      params.push(['timeInForce', 'GTC']);
      params.push(['quantity', String(qty)]);
      params.push(['price', String(price)]);
    } else if (typ === 'MARKET') {
      if (market === 'spot' && sideU === 'BUY') params.push(['quoteOrderQty', String(qty)]);
      else params.push(['quantity', String(qty)]);
    } else {
      if (f.closePosition) params.push(['closePosition', 'true']);
      else params.push(['quantity', String(qty)]);
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

  // ── Arcus pure helpers ────────────────────────────────────────────────────
  function arcusParseCreds(secret) {
    var s = String(secret == null ? '' : secret).trim();
    var idx = 0;
    var ci = s.indexOf(':');
    if (ci >= 0) {
      var idxS = s.slice(ci + 1).trim();
      s = s.slice(0, ci).trim();
      idx = idxS === '' ? 0 : parseInt(idxS, 10);
      if (isNaN(idx) || String(idx) !== idxS && idxS !== '') {
        if (!/^\d+$/.test(idxS)) throw new Error("Account index after ':' must be a number 0-9");
      }
    }
    if (s.slice(0, 2).toLowerCase() === '0x') s = s.slice(2);
    s = s.toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(s)) {
      throw new Error('Arcus secret must be the 64-hex Ed25519 private key'
                      + ' seed (optionally \':accountIndex\')');
    }
    if (!(idx >= 0 && idx <= 9)) throw new Error('Account index must be between 0 and 9');
    return [s, idx];
  }
  function arcusPubkeyHex(seedHex) {
    return bytesToHex(edPubkeyBytes(seedHex));
  }
  // X-Timestamp: unix NANOSECONDS (BigInt-safe; ms/s epochs are 401s)
  function arcusTsNs(nowMs) {
    var ms = nowMs != null ? Math.round(nowMs) : Date.now();
    return BigInt(ms) * 1000000n;
  }
  // Compact JSON, BigInt-safe, matching Python json.dumps(..., sort_keys=?,
  // separators=(',',':'), ensure_ascii=True). Payload/body values here are
  // ASCII strings, ints, bools — the escape set is the JSON.stringify one.
  function jsonCompactBig(obj, sortKeys) {
    if (obj === null || obj === undefined) return 'null';
    if (typeof obj === 'bigint') return obj.toString();
    if (typeof obj === 'boolean') return obj ? 'true' : 'false';
    if (typeof obj === 'number') {
      if (!Number.isInteger(obj)) throw new Error('float in signing JSON — refuse (fail loud)');
      return String(obj);
    }
    if (typeof obj === 'string') return JSON.stringify(obj);
    if (Array.isArray(obj)) {
      var items = [];
      for (var i = 0; i < obj.length; i++) items.push(jsonCompactBig(obj[i], sortKeys));
      return '[' + items.join(',') + ']';
    }
    var keys = Object.keys(obj);
    if (sortKeys) keys.sort();
    var parts = [];
    for (var j = 0; j < keys.length; j++) {
      parts.push(JSON.stringify(keys[j]) + ':' + jsonCompactBig(obj[keys[j]], sortKeys));
    }
    return '{' + parts.join(',') + '}';
  }
  function arcusCanonicalJson(obj) { return jsonCompactBig(obj, true); }
  function arcusJson(obj) { return jsonCompactBig(obj, false); }
  function arcusSign(seedHex, message) {
    return edSignHex(seedHex, utf8Bytes(message));
  }
  function arcusSignPayload(seedHex, payload) {
    return arcusSign(seedHex, arcusCanonicalJson(payload));
  }
  function arcusSignAction(seedHex, tsNs, action, body) {
    return arcusSign(seedHex, String(tsNs) + String(action) + arcusCanonicalJson(body));
  }
  // Human decimal → engine-native integer (÷ tick or step); exact-multiple only
  function arcusToUnits(value, unit) {
    var v = dxParse(value), u = dxParse(unit);
    if (dxCmpZero(u) <= 0) throw new Error('bad unit');
    var num = v.digits * dxPow10(u.scale);
    var den = u.digits * dxPow10(v.scale);
    if (num % den !== 0n) throw new Error(String(value) + ' is not a multiple of ' + String(unit));
    var q = num / den;
    return v.neg ? -q : q;               // BigInt (serialized bare by arcusJson)
  }
  function arcusClientId(clOrdID) {
    var s = String(clOrdID == null ? '' : clOrdID), out = '';
    for (var i = 0; i < s.length && out.length < 36; i++) {
      var c = s.charAt(i);
      if (/[A-Za-z0-9_-]/.test(c)) out += c;
    }
    return out;
  }
  var ARC_SIDE = { buy: 0, sell: 1 };
  var ARC_TIF = { GTT: 0, FOK: 1, IOC: 2, ALO: 3 };
  function arcusMarketBoundPrice(mark, tick, side) {
    var m = dxParse(mark == null || mark === '' ? '0' : mark);
    var t = dxParse(tick);
    if (dxCmpZero(m) <= 0 || dxCmpZero(t) <= 0) throw new Error('mark price unavailable');
    // buy → mark×1.1 floored to tick; sell → mark×0.9 ceiled to tick
    var scaled = dxMulSmall(m, String(side).toLowerCase() === 'buy' ? 110n : 90n, 2);
    var num = scaled.digits * dxPow10(t.scale);
    var den = t.digits * dxPow10(scaled.scale);
    var ticks = num / den;
    if (String(side).toLowerCase() !== 'buy' && num % den !== 0n) ticks += 1n;
    if (ticks <= 0n) throw new Error('mark price unavailable');
    var px = { neg: false, digits: ticks * t.digits, scale: t.scale };
    return dxFmt(px);
  }
  // PURE → { body, payload } for POST /v1/placeOrder (arcus_place_bodies parity)
  function arcusPlaceBodies(address, accountIndex, spec, side, ordType, qty,
                            price, clOrdID, opts) {
    var o = opts || {};
    var nowMs = o.nowMs != null ? Math.round(o.nowMs) : Date.now();
    var ct = arcusTsNs(nowMs);
    var tick = spec.tick, step = spec.qty_step;
    var marketId = parseInt(spec.market_id, 10);
    if (!tick || !step) throw new Error('market spec is missing tick/step');
    var pInt = arcusToUnits(price, tick);
    var qInt = arcusToUnits(qty, step);
    var sInt = ARC_SIDE[String(side).toLowerCase()];
    if (sInt === undefined) throw new Error('bad side');
    var isMarket = String(ordType).toLowerCase() === 'market';
    var tif = isMarket ? 'IOC' : 'GTT';
    var cid = arcusClientId(clOrdID);
    var body = {
      address: String(address),
      accountIndex: accountIndex,
      marketId: marketId,
      orderSide: sInt === 0 ? 'BUY' : 'SELL',
      orderType: isMarket ? 'MARKET' : 'LIMIT',
      quantity: String(qty),
      price: String(price),
      timeInForce: tif,
      timestamp: ct,
      clientTime: String(nowMs),
    };
    var g = 0n;
    if (tif === 'GTT') {
      var gttUs = (BigInt(nowMs) + BigInt(ARCUS_GTT_DAYS * 86400) * 1000n) * 1000n;
      body.goodTilTime = gttUs.toString();
      g = gttUs * 1000n;
    }
    if (cid) body.clientId = cid;
    if (o.reduceOnly) body.reduceOnly = true;
    var payload = {
      ad: String(address).toLowerCase(), ai: accountIndex, ct: ct, g: g,
      m: marketId, op: 1, p: pInt, q: qInt,
      r: o.reduceOnly ? 1 : 0, s: sInt, t: ARC_TIF[tif], v: 1,
    };
    if (cid) payload.c = cid;
    return { body: body, payload: payload };
  }
  // PURE → { body, payload } for POST /v1/cancelOrder (CancelByOrderId shape)
  function arcusCancelBodies(address, accountIndex, marketId, orderId, opts) {
    var o = opts || {};
    var ct = arcusTsNs(o.nowMs);
    var body = {
      orderId: String(orderId),
      address: String(address),
      marketId: parseInt(marketId, 10),
      accountIndex: accountIndex,
      timestamp: ct,
    };
    var payload = {
      ad: String(address).toLowerCase(), ai: accountIndex, ct: ct,
      id: String(orderId), m: parseInt(marketId, 10), op: 2, v: 1,
    };
    return { body: body, payload: payload };
  }
  function arcusErrorMessage(data, status) {
    if (data && typeof data === 'object') {
      var keys = ['rejectionReason', 'error', 'message', 'reason'];
      for (var i = 0; i < keys.length; i++) {
        if (data[keys[i]]) return 'Arcus: ' + data[keys[i]];
      }
    }
    return 'Arcus returned HTTP ' + status;
  }

  return {
    // constants
    HL_API_BASE: HL_API_BASE,
    ASTER_FUT_BASE: ASTER_FUT_BASE,
    ASTER_SPOT_BASE: ASTER_SPOT_BASE,
    ARCUS_BASE: ARCUS_BASE,
    HL_SPOT_ASSET_OFFSET: HL_SPOT_ASSET_OFFSET,
    HL_BUILDER_ASSET_BASE: HL_BUILDER_ASSET_BASE,
    HL_BUILDER_ASSET_STRIDE: HL_BUILDER_ASSET_STRIDE,
    HL_MARKET_SLIP_PCT: HL_MARKET_SLIP_PCT,
    ARCUS_MARKET_SLIP_PCT: ARCUS_MARKET_SLIP_PCT,
    ARCUS_GTT_DAYS: ARCUS_GTT_DAYS,
    // primitives (parity-tested)
    hexToBytes: hexToBytes,
    bytesToHex: bytesToHex,
    utf8Bytes: utf8Bytes,
    keccak256: keccak256,
    sha256: sha256,
    sha512: sha512,
    md5: md5,
    hmacSha256: hmacSha256,
    msgpackEncode: msgpackEncode,
    secpSignDigest: secpSignDigest,
    edPubkeyBytes: edPubkeyBytes,
    edSignHex: edSignHex,
    eip712DomainSep: eip712DomainSep,
    eip712Digest: eip712Digest,
    // Hyperliquid
    hlNextNonce: hlNextNonce,
    hlWireNum: hlWireNum,
    hlPxDecimals: hlPxDecimals,
    hlRoundPx: hlRoundPx,
    hlRoundSz: hlRoundSz,
    hlSizeFromQuote: hlSizeFromQuote,
    hlCloid: hlCloid,
    hlOrderWire: hlOrderWire,
    hlActionHash: hlActionHash,
    hlSignAction: hlSignAction,
    hlSignerAddress: hlSignerAddress,
    hlCoinIsSpot: hlCoinIsSpot,
    hlOrderPlan: hlOrderPlan,
    hlCancelAction: hlCancelAction,
    hlExchangeResult: hlExchangeResult,
    // AsterDex
    urlencodePy: urlencodePy,
    asterNextNonce: asterNextNonce,
    asterSignParams: asterSignParams,
    asterOrderParams: asterOrderParams,
    // Arcus
    arcusParseCreds: arcusParseCreds,
    arcusPubkeyHex: arcusPubkeyHex,
    arcusTsNs: arcusTsNs,
    arcusCanonicalJson: arcusCanonicalJson,
    arcusJson: arcusJson,
    arcusSign: arcusSign,
    arcusSignPayload: arcusSignPayload,
    arcusSignAction: arcusSignAction,
    arcusToUnits: arcusToUnits,
    arcusClientId: arcusClientId,
    arcusMarketBoundPrice: arcusMarketBoundPrice,
    arcusPlaceBodies: arcusPlaceBodies,
    arcusCancelBodies: arcusCancelBodies,
    arcusErrorMessage: arcusErrorMessage,
  };
}));
