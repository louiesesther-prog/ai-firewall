// ── Enterprise License (Open Core) ─────────────────────────────────
// Open-core monetization: the core scanner is free (MIT). Team and
// Enterprise tiers unlock the enterprise modules and are gated by a
// signed license key.
//
// Key format:  AIFW-<TIER>-<payloadB64url>-<sigHex>
//   - TIER      : team | enterprise
//   - payload   : base64url(JSON { org, seats, issued, exp })
//   - sig       : hex(HMAC-SHA256(payload, signingKey))
//
// A blank / Community install needs no license key (free core). Setting
// a Team/Enterprise key unlocks the matching features via the flags.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const TIERS = ['community', 'team', 'enterprise'];
const TIER_ORDER = { community: 0, team: 1, enterprise: 2 };

// Secrets — override for production. Defaults are deterministic so tests
// and local evaluation work without configuration.
function getSecret(name) {
  if (process.env[name]) return process.env[name];
  return crypto.createHash('sha256').update('ai-firewall-' + name).digest('hex');
}
const SIGNING_KEY = getSecret('AIFW_LICENSE_SIGNING_KEY');

function b64u(s) { return Buffer.from(s, 'utf8').toString('base64url'); }
function unb64u(s) { return Buffer.from(s, 'base64url').toString('utf8'); }

// Creates a signed key for internal/generator use.
function createKey({ tier = 'enterprise', org = 'Acme', seats = 0, expDays = 365 } = {}) {
  if (!TIERS.includes(tier)) throw new Error('Invalid tier: ' + tier + ' (team|enterprise)');
  const payload = { tier, org, seats: seats | 0, issued: Date.now(), exp: Date.now() + expDays * 86400000 };
  const p = b64u(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', SIGNING_KEY).update(p).digest('hex');
  return 'AIFW-' + tier + '-' + p + '-' + sig;
}

function parseKey(key) {
  if (!key || typeof key !== 'string') return null;
  const m = key.trim().match(/^AIFW-(-?[a-z]+)-([A-Za-z0-9_-]+)-([0-9a-f]{64})$/);
  if (!m) return null;
  return { tier: m[1], payload: m[2], sig: m[3].toLowerCase() };
}

// Verifies a key's signature and validity window; returns normalized license
// object or throws with a human-readable reason.
function verifyKey(key) {
  const parsed = parseKey(key);
  if (!parsed) {
    const e = new Error('Malformed license key');
    e.code = 'BAD_FORMAT';
    throw e;
  }
  const expected = crypto.createHmac('sha256', SIGNING_KEY).update(parsed.payload).digest('hex');
  if (expected !== parsed.sig) {
    const e = new Error('License signature mismatch');
    e.code = 'BAD_SIGNATURE';
    throw e;
  }
  if (!TIERS.includes(parsed.tier)) {
    const e = new Error('Unknown license tier: ' + parsed.tier);
    e.code = 'BAD_TIER';
    throw e;
  }
  const data = JSON.parse(unb64u(parsed.payload));
  if (data.exp && Date.now() > data.exp) {
    const e = new Error('License expired ' + new Date(data.exp).toISOString());
    e.code = 'EXPIRED';
    throw e;
  }
  return {
    tier: parsed.tier,
    org: data.org || '—',
    seats: data.seats || 0,
    issued: data.issued,
    exp: data.exp || null,
  };
}

// Loads the configured key from env or the closest .license file.
function loadKey() {
  if (process.env.AIFW_LICENSE_KEY) return process.env.AIFW_LICENSE_KEY;
  const candidates = ['.license', path.join(process.cwd(), '.license')];
  for (const c of candidates) {
    try { if (fs.existsSync(c)) return fs.readFileSync(c, 'utf8').toString().trim(); } catch (e) { /* ignore */ }
  }
  return null;
}

// Current active tier, with a reason when a key is missing/invalid.
function current() {
  const key = loadKey();
  const raw = process.env.AIFW_LICENSE_KEY;
  if (!key && !raw) {
    return { tier: 'community', unlocked: false, keyMissing: true, reason: 'no-key', license: null };
  }
  try {
    const lic = verifyKey(key);
    return { tier: lic.tier, unlocked: true, keyMissing: false, reason: 'ok', license: lic };
  } catch (e) {
    return { tier: 'community', unlocked: false, keyMissing: false, reason: e.code, error: e.message, license: null };
  }
}

// True when the license tier is at or above `minTier`.
function satisfies(minTier) {
  const c = current();
  return TIER_ORDER[c.tier] >= (TIER_ORDER[minTier] || 0);
}

module.exports = { createKey, verifyKey, parseKey, current, satisfies, loadKey, TIERS, getSecret };
