(function (global) {
  'use strict';

  // AI Personal Firewall — client-side Pro license gate.
  // The key format is deterministic so a web validator and a server CLI can
  // both verify, but brute-forcing a valid key is impractical without knowing
  // the secret salt below. Change the salt BEFORE going live.
  var SALT = 'ai-firewall-pro-87e3f9c1';

  var STORE_KEY = 'aifw_pro_session';
  var KEY_STORE = 'aifw_pro_key';
  var MAX_SESSION_DAYS = 90;

  // ── key format: PRO-XXXX-XXXX-XXXX ──
  // Each XXXX is 4 uppercase hex digits. The last group is a checksum of the
  // first two groups so not every string unlocks the gate.
  var KEY_RE = /^PRO-([0-9A-F]{4})-([0-9A-F]{4})-([0-9A-F]{4})$/;

  function hashFnv1a(parts) {
    var h = 0x811c9dc5;
    var str = SALT + '|' + parts.join('|');
    for (var i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 0x01000193);
    }
    return h >>> 0;
  }

  function checksum(randA, randB) {
    var h = hashFnv1a([randA, randB, 'chk']);
    return ('0000' + h.toString(16).toUpperCase()).slice(-4);
  }

  function generate() {
    var a = Math.random().toString(16).slice(2, 6).toUpperCase();
    var b = Math.random().toString(16).slice(2, 6).toUpperCase();
    // ensure exactly 4 hex chars
    a = ('0000' + a).slice(-4);
    b = ('0000' + b).slice(-4);
    a = a.replace(/[^0-9A-F]/g, '0');
    b = b.replace(/[^0-9A-F]/g, '0');
    return 'PRO-' + a + '-' + b + '-' + checksum(a, b);
  }

  function isValid(key) {
    if (!key) return false;
    var m = KEY_RE.exec(key.trim().toUpperCase());
    if (!m) return false;
    var exp = checksum(m[1], m[2]);
    return m[3] === exp;
  }

  // ── session ──
  function unlock(email, key) {
    if (!isValid(key)) return false;
    var now = Date.now();
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify({ email: email || '', key: key, at: now, exp: now + MAX_SESSION_DAYS * 86400000 }));
      localStorage.setItem(KEY_STORE, key);
    } catch (e) { /* storage may be blocked */ }
    return true;
  }

  function session() {
    try {
      var raw = localStorage.getItem(STORE_KEY);
      if (!raw) return null;
      var o = JSON.parse(raw);
      if (o && o.exp && o.exp > Date.now()) return o;
      if (o) lock();
      return null;
    } catch (e) { return null; }
  }

  function lock() {
    try {
      localStorage.removeItem(STORE_KEY);
    } catch (e) {}
  }

  global.AIFW = global.AIFW || {};
  global.AIFW.pro = {
    isValid: isValid,
    generate: generate,
    unlock: unlock,
    session: session,
    lock: lock
  };
})(typeof window !== 'undefined' ? window : globalThis);