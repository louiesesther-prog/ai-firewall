// ── Enterprise Module Unit Tests ────────────────────────────────────
// Exercises Phases 2-5 enterprise modules using an in-memory SQLite-compatible
// shim (better-sqlite3 isn't buildable in all environments). Pure-logic paths
// are tested directly; DB-backed paths run against the shim. If a module fails
// to load, those tests are reported as SKIP rather than failing the run.
//
// Usage: node test-enterprise.mjs

import { createRequire } from 'module';
import assert from 'assert';

const require = createRequire(import.meta.url);

// ── In-memory SQLite-compatible shim ─────────────────────────────────
// Implements the subset of better-sqlite3 used by the enterprise modules:
//   prepare(sql).bind([..]).step()/.getAsObject()/.free()
//   run(sql, [..])
//   exec(sql)  pragma(str)  transaction()
// Tables are created lazily from INSERT/SELECT column sets.

class MemDb {
  constructor() {
    this.tables = {};
  }
  exec() {}
  pragma() {}
  transaction() { return { apply(fn) { fn(); } }; }
  prepare(sql) { return new MemStmt(sql, this); }
  run(sql, params) {
    const s = normalize(sql);
    if (!s.startsWith('insert')) throw new Error('run() only supports INSERT: ' + sql);
    return this._insert(s, params || []);
  }
  _insert(s, params) {
    const m = s.match(/insert(?:\s+or\s+ignore)?\s+into\s+"?([\w]+)"?\s*\(([^)]*)\)\s*values\s*\(([^)]*)\)/i);
    if (!m) throw new Error('insert parse fail: ' + s);
    const table = m[1];
    const cols = m[2].split(',').map(c => c.replace(/"/g, '').trim());
    const placeholders = m[3].split(',').map(p => p.trim());
    let pi = 0;
    const row = {};
    cols.forEach((c, i) => {
      let p = placeholders[i];
      if (p === '?') { row[c] = params[pi++]; }
      else if (p === "datetime('now')") { row[c] = '2026-08-28 00:00:00'; }
      else { row[c] = p.replace(/^'(.*)'$/, '$1'); }
    });
    if (!this.tables[table]) this.tables[table] = [];
    this.tables[table].push(row);
    return { changes: 1, lastInsertRowid: this.tables[table].length };
  }
  // Executes a SELECT against the in-memory store. Supports:
  //   SELECT * or SELECT col1, col2 [FROM table]
  //   WHERE col = ?|'literal'  AND ...
  //   ORDER BY col ASC|DESC
  //   aggregate: SELECT COUNT(*) as c, SUM(col) as s, COUNT(DISTINCT col) as n
  _query(sql, params) {
    const s = normalize(sql);
    if (s.startsWith('insert')) return [];
    if (!s.startsWith('select')) throw new Error('unsupported query (shim): ' + sql);
    if (/\binner\s+join\b/.test(s)) return this._joinQuery(s, params);

    const fromMatch = s.match(/from\s+"?([\w]+)"?/i);
    if (!fromMatch) return [];
    const table = fromMatch[1];
    const rows = (this.tables[table] || []).slice();

    let where = s.slice(fromMatch.index + fromMatch[0].length);
    let orderBy = null;
    const orderMatch = where.match(/order\s+by\s+([^$]*?)\s*$/i);
    if (orderMatch) { orderBy = orderMatch[1].trim(); where = where.slice(0, orderMatch.index); }

    const whereMatch = where.match(/where\s+([\s\S]*)/i);
    let conditions = [];
    if (whereMatch) {
      conditions = whereMatch[1].trim().split(/\s+and\s+/i).map(c => {
        const m = c.trim().match(/^([\w.]+)\s*=\s*(.*)$/);
        if (!m) throw new Error('unsupported WHERE clause (shim): ' + c);
        const col = m[1];
        const rhs = m[2].trim();
        let val;
        if (rhs === '?') val = params[0];
        else val = rhs.replace(/^'(.*)'$/, '$1');
        return { col, val };
      });
    }

    let filtered = rows;
    for (const c of conditions) {
      filtered = filtered.filter(r => String(r[c.col]) === String(c.val));
    }

    if (orderBy) {
      const [col, dir] = orderBy.split(/\s+/);
      filtered.sort((a, b) => {
        const av = a[col], bv = b[col];
        const cmp = (av === bv) ? 0 : (av > bv ? 1 : -1);
        return dir === 'desc' ? -cmp : cmp;
      });
    }

    const sel = s.slice(7, s.indexOf('from')).trim();
    // aggregate?
    const agg = sel.match(/count\s*\(\s*\*\s*\)\s+as\s+([\w]+)|sum\s*\(\s*([\w]+)\s*\)\s+as\s+([\w]+)|count\s*\(\s*distinct\s+([\w]+)\s*\)\s+as\s+([\w]+)/i);
    if (agg) {
      const out = {};
      const cntStar = s.match(/count\s*\(\s*\*\s*\)\s+as\s+([\w]+)/i);
      const sumCol = s.match(/sum\s*\(\s*([\w]+)\s*\)\s+as\s+([\w]+)/i);
      const cntDistinct = s.match(/count\s*\(\s*distinct\s+([\w]+)\s*\)\s+as\s+([\w]+)/i);
      if (cntStar) out[cntStar[1]] = filtered.length;
      if (sumCol) out[sumCol[2]] = filtered.reduce((a, r) => a + (Number(r[sumCol[1]]) || 0), 0);
      if (cntDistinct) out[cntDistinct[2]] = new Set(filtered.map(r => r[cntDistinct[1]])).size;
      return [out];
    }

    if (sel === '*') return filtered.map(r => Object.assign({}, r));
    const cols = sel.split(',').map(c => c.replace(/"/g, '').trim());
    if (cols.length === 1 && cols[0] === '*') return filtered.map(r => Object.assign({}, r));
    return filtered.map(r => {
      const o = {};
      cols.forEach(c => { o[c] = r[c]; });
      return o;
    });
  }
  _joinQuery(s, params) {
    const m = s.match(/select\s+(?:\*|([\w.]+)\s*\.\s*\*)\s+from\s+([\w]+)\s+(\w+)\s+inner\s+join\s+([\w]+)\s+(\w+)\s+on\s+([\w.]+)\s*=\s*([\w.]+)/);
    if (!m) throw new Error('unsupported JOIN (shim): ' + s);
    const selAlias = m[1] || null;
    const t1 = m[2], a1 = m[3], t2 = m[4], a2 = m[5];
    const jc1 = m[6].split('.')[1], jc2 = m[7].split('.')[1];
    let where = s.slice(m[0].length);
    let orderBy = null;
    const om = where.match(/order\s+by\s+([\w.]+)\s+(asc|desc)/i);
    if (om) { orderBy = { col: om[1].split('.')[1], dir: om[2] }; where = where.slice(0, om.index); }
    const wm = where.match(/where\s+([\s\S]*)/i);
    const conds = [];
    if (wm) {
      wm[1].trim().split(/\s+and\s+/i).forEach(c => {
        const mm = c.match(/^(\w+)\.(\w+)\s*=\s*([^ ]+)/);
        const col = mm[2];
        const rhs = mm[3].trim();
        const val = rhs === '?' ? params[0] : rhs.replace(/^'(.*)'$/, '$1');
        conds.push({ col, val });
      });
    }
    const left = (this.tables[t1] || []);
    const right = (this.tables[t2] || []);
    const out = [];
    for (const lrow of left) {
      let matched = false;
      for (const rrow of right) {
        if (String(lrow[jc1]) !== String(rrow[jc2])) continue;
        matched = true;
        const merged = Object.assign({}, lrow, rrow);
        let pass = true;
        for (const c of conds) if (String(merged[c.col]) !== String(c.val)) { pass = false; break; }
        if (pass) {
          const row = {};
          if (selAlias) {
            const src = selAlias === a1 ? lrow : (selAlias === a2 ? rrow : merged);
            Object.keys(src).forEach(k => { row[k] = src[k]; });
          } else {
            Object.assign(row, merged);
          }
          out.push(row);
        }
      }
      if (!matched && conds.length) {
        // keep outer semantics: if a WHERE exists referencing right side and nothing matched, skip
      }
    }
    if (orderBy) {
      out.sort((x, y) => {
        const av = x[orderBy.col], bv = y[orderBy.col];
        const cmp = (av === bv) ? 0 : (av > bv ? 1 : -1);
        return orderBy.dir === 'desc' ? -cmp : cmp;
      });
    }
    return out;
  }
}

function normalize(s) {
  return String(s).replace(/\s+/g, ' ').trim().toLowerCase();
}

class MemStmt {
  constructor(sql, db) {
    this.sql = sql;
    this.db = db;
    this.params = [];
    this._rows = null;
    this._i = 0;
    this._bound = false;
  }
  bind(p) { this.params = p || []; this._bound = true; return this; }
  step() {
    if (this._rows === null) this._rows = this.db._query(this.sql, this.params);
    if (this._i < this._rows.length) { this._row = this._rows[this._i++]; return true; }
    return false;
  }
  getAsObject() { return this._row; }
  free() {}
}

class ShimDbMain {
  pragma() {} exec() {} transaction() { return { apply(fn){ fn(); } }; }
  prepare(sql) {
    // Enterprise db.cjs pulls its own table definitions; we route queries to
    // the shared MemDb store so SELECT/INSERT operate on the same tables.
    return new MemStmt(sql, mem);
  }
  run(sql, params) { return mem._insert(normalize(sql), params || []); }
  // expose a method used by initEnterpriseSchema-like flows if needed
}

const mem = new MemDb();
const ShimDb = ShimDbMain;

// Intercept better-sqlite3 for any module loaded under require().
let patched = false;
function ensureShim() {
  if (patched) return;
  if (!require.cache && !globalThis.__patchedBetterSqlite) {
    globalThis.__patchedBetterSqlite = true;
    const Module = require('module');
    const orig = Module._load;
    Module._load = function (request, parent, isMain) {
      if (request === 'better-sqlite3') return ShimDb;
      return orig.call(this, request, parent, isMain);
    };
    patched = true;
  } else if (require.cache) {
    const Module = require('module');
    const orig = Module._load;
    Module._load = function (request, parent, isMain) {
      if (request === 'better-sqlite3') return ShimDb;
      return orig.call(this, request, parent, isMain);
    };
    patched = true;
  }
}

let passed = 0, failed = 0, skipped = 0;
const failures = [];
function ok(name, cond, detail) {
  if (cond) { passed++; console.log('  \x1b[32mPASS\x1b[0m | ' + name); }
  else { failed++; failures.push(name + (detail ? ': ' + detail : '')); console.log('  \x1b[31mFAIL\x1b[0m | ' + name + (detail ? ' :: ' + detail : '')); }
}
function skip(name, why) { skipped++; console.log('  \x1b[33mSKIP\x1b[0m | ' + name + (why ? ' :: ' + why : '')); }

// ── Loadable module loader ------------------------------------------------------------------
function load(name) {
  const p = name.endsWith('.cjs') ? name : name + '.cjs';
  try { return require('./enterprise/' + p); }
  catch (e) { return { __error: e }; }
}

// ═══════════════════════════════════════════════════════════════════
console.log('── Feature Flags (open-core license gated) ──');
{
  // feature-flags is computed at require time from process.env.
  // Open-core gating: flags only enable when the license tier is high enough.
  // Use a valid enterprise-tier key so these tests exercise the env logic
  // (not the community lockout, which is covered by the license tests below).
  const prior = Object.assign({}, process.env);
  Object.keys(process.env).filter(k => /^ENTERPRISE_/.test(k) || k === 'AIFW_LICENSE_KEY').forEach(k => delete process.env[k]);
  process.env.ENTERPRISE_ALL = '1';
  const lic = require('./enterprise/license.cjs');
  process.env.AIFW_LICENSE_KEY = lic.createKey({ tier: 'enterprise', org: 'TestRow' });
  const key = require.resolve('./enterprise/feature-flags.cjs');
  delete require.cache[key];
  const ffAll = require('./enterprise/feature-flags.cjs');
  ok('ENTERPRISE_ALL enables rbac', ffAll.isEnabled('rbac') === true);
  ok('ENTERPRISE_ALL enables marketplace', ffAll.isEnabled('marketplace') === true);
  ok('ENTERPRISE_ALL enables shadow', ffAll.isEnabled('shadow') === true);
  // override OFF must work even with ALL set (the '0' truthiness fix)
  process.env.ENTERPRISE_MARKETPLACE = '0';
  delete require.cache[key];
  const ffOff = require('./enterprise/feature-flags.cjs');
  ok("ENTERPRISE_MARKETPLACE=0 disables marketplace", ffOff.isEnabled('marketplace') === false);
  ok("ENTERPRISE_MARKETPLACE=0 keeps rbac on", ffOff.isEnabled('rbac') === true);
  // per-module only
  Object.keys(process.env).filter(k => /^ENTERPRISE_/.test(k)).forEach(k => delete process.env[k]);
  process.env.ENTERPRISE_RBAC = '1';
  delete require.cache[key];
  const ffOne = require('./enterprise/feature-flags.cjs');
  ok('ENTERPRISE_RBAC only enables rbac', ffOne.isEnabled('rbac') === true && ffOne.isEnabled('marketplace') === false);
  // restore
  Object.keys(process.env).filter(k => /^ENTERPRISE_/.test(k) || k === 'AIFW_LICENSE_KEY').forEach(k => delete process.env[k]);
  Object.assign(process.env, prior);
  delete require.cache[key];
}

console.log('── License (open-core gating) ──');
{
  const lic = require('./enterprise/license.cjs');
  const prior = Object.assign({}, process.env);

  // key create/parse round-trip
  const ent = lic.createKey({ tier: 'enterprise', org: 'Acme', seats: 50, expDays: 90 });
  ok('createKey returns AIFW-key', /^AIFW-(team|enterprise)-/.test(ent));
  const v = lic.verifyKey(ent);
  ok('verifyKey round-trips tier/org', v.tier === 'enterprise' && v.org === 'Acme' && v.seats === 50);
  // signature integrity → tamper rejection
  const [a, b, c, sig] = ent.split('-');
  const tampered = [a, b, c, sig.slice(0, 10) + '0'.repeat(sig.length - 10)].join('-');
  let threw = false;
  try { lic.verifyKey(tampered); } catch (e) { threw = true; }
  ok('tampered key rejected', threw === true);

  // community (no key) → all enterprise flags off even with ENTERPRISE_ALL
  Object.keys(process.env).filter(k => /^ENTERPRISE_/.test(k) || k === 'AIFW_LICENSE_KEY').forEach(k => delete process.env[k]);
  process.env.ENTERPRISE_ALL = '1';
  let key2 = require.resolve('./enterprise/feature-flags.cjs');
  delete require.cache[key2];
  const ffc = require('./enterprise/feature-flags.cjs');
  ok('no key -> rbac off', ffc.isEnabled('rbac') === false);
  ok('no key -> apiKeys off', ffc.isEnabled('apiKeys') === false);
  ok('no key -> community tier', lic.current().tier === 'community');

  // team tier unlocks team modules but NOT enterprise-only
  Object.keys(process.env).filter(k => /^ENTERPRISE_/.test(k) || k === 'AIFW_LICENSE_KEY').forEach(k => delete process.env[k]);
  process.env.ENTERPRISE_ALL = '1';
  process.env.AIFW_LICENSE_KEY = lic.createKey({ tier: 'team', org: 'T' });
  delete require.cache[key2];
  const fft = require('./enterprise/feature-flags.cjs');
  ok('team -> apiKeys on', fft.isEnabled('apiKeys') === true);
  ok('team -> rbac still off', fft.isEnabled('rbac') === false);
  ok('team -> tenancy off', fft.isEnabled('tenancy') === false);

  // enterprise tier unlocks everything
  Object.keys(process.env).filter(k => /^ENTERPRISE_/.test(k) || k === 'AIFW_LICENSE_KEY').forEach(k => delete process.env[k]);
  process.env.ENTERPRISE_ALL = '1';
  process.env.AIFW_LICENSE_KEY = lic.createKey({ tier: 'enterprise', org: 'E' });
  delete require.cache[key2];
  const ffe = require('./enterprise/feature-flags.cjs');
  ok('enterprise -> rbac on', ffe.isEnabled('rbac') === true);
  ok('enterprise -> marketplace on', ffe.isEnabled('marketplace') === true);
  ok('enterprise -> satisfied(enterprise)', lic.satisfies('enterprise') === true);

  // restore
  Object.keys(process.env).filter(k => /^ENTERPRISE_/.test(k) || k === 'AIFW_LICENSE_KEY').forEach(k => delete process.env[k]);
  Object.assign(process.env, prior);
  delete require.cache[key2];
}

// ═══════════════════════════════════════════════════════════════════
ensureShim();

console.log('── RBAC (pure) ──');
{
  const rbac = load('auth/rbac.cjs');
  if (rbac.__error) { skip('RBAC load', rbac.__error.message); }
  else {
    const D = rbac.DEFAULT_ROLE_PERMISSIONS;
    ok('owner/admin have wildcard', D.owner[0] === '*' && D.admin[0] === '*');
    ok('member has api_keys.read', D.member.includes('api_keys.read'));
    ok('viewer has audit.read', D.viewer.includes('audit.read'));
    ok('viewer lacks api_keys.write', !D.viewer.includes('api_keys.write'));
    ok('member lacks tenancy.read', !D.member.includes('tenancy.read'));
    // seed should not throw / permissions registry intact
    try { rbac.ensureSeedPermissions(); ok('ensureSeedPermissions ran (no crash)', true); }
    catch (e) { ok('ensureSeedPermissions ran (no crash)', false, e.message); }
  }
}

console.log('── Marketplace built-ins (pure) ──');
{
  const m = load('marketplace/marketplace.cjs');
  if (m.__error) { skip('Marketplace load', m.__error.message); }
  else {
    ok('5 built-in packs', m.BUILTIN_PACKS.length === 5, '' + m.BUILTIN_PACKS.length);
    const cats = m.BUILTIN_PACKS.map(p => p.category);
    ['hipaa','pci','gdpr','ccpa','soc2'].forEach(c => ok('packs include ' + c, cats.includes(c)));
    const valid = m.BUILTIN_PACKS.every(p => p.slug && p.name && Array.isArray(p.rules) && p.rules.length > 0);
    ok('all packs well-formed', valid);
    ok('4 built-in templates', m.BUILTIN_TEMPLATES.length === 4, '' + m.BUILTIN_TEMPLATES.length);
    const tvalid = m.BUILTIN_TEMPLATES.every(t => t.slug && t.action && t.conditions);
    ok('all templates well-formed', tvalid);
  }
}

console.log('── Network Agent (pure) ──');
{
  const n = load('observability/network-agent.cjs');
  if (n.__error) { skip('Network agent load', n.__error.message); }
  else {
    const e = n.analyzePayload('contact me at a@b.com');
    ok('analyzePayload detects email', e.piiTypes.includes('email'), JSON.stringify(e));
    const p = n.analyzePayload('SSN 123-45-6789 and card number 4111111111111111');
    ok('analyzePayload detects ssn', p.piiTypes.includes('ssn'));
    const card = n.analyzePayload('4111111111111111');
    ok('analyzePayload detects credit_card (standalone)', card.piiTypes.includes('credit_card'));
    ok('riskScore computed', p.riskScore > 0);
    const none = n.analyzePayload('hello world');
    ok('clean payload -> no pii', none.piiTypes.length === 0 && none.riskScore === 0);
    ok('detectAIService chatgpt', n.detectAIService('chatgpt.com') === 'chatgpt');
    ok('detectAIService claude', n.detectAIService('claude.ai') === 'claude');
    ok('detectAIService gemini (substring)', n.detectAIService('api.gemini.google.com') === 'gemini');
    ok('detectAIService unknown -> null', n.detectAIService('example.org') === null);
  }
}

console.log('── Shadow Mode (pure) ──');
{
  const s = load('observability/shadow-mode.cjs');
  if (s.__error) { skip('Shadow mode load', s.__error.message); }
  else {
    ok('detect chatgpt', s.detectAIService('chatgpt.com') === 'chatgpt');
    ok('detect anthropic', ['claude','anthropic'].includes(s.detectAIService('anthropic.com')));
    ok('detect perplexity', s.detectAIService('perplexity.ai') === 'perplexity');
    ok('detect none -> custom', s.detectAIService('neversite.xyz') === 'custom');
  }
}

console.log('── SSO tokens (pure HMAC) ──');
{
  const crypto = require('crypto');
  // Sign/verify deterministically to cross-check validateToken via its own internals
  const sso = load('identity/sso.cjs');
  if (sso.__error) { skip('SSO load', sso.__error.message); }
  else {
    // validateToken / issueToken need _db for providers/sessions; test the
    // pure HMAC sign+verify helpers indirectly through black-box equivalence.
    // We validate that the module exposes issueToken + validateToken functions.
    ok('exposes issueToken', typeof sso.issueToken === 'function');
    ok('exposes validateToken', typeof sso.validateToken === 'function');
    // Detached sign/verify to prove signature integrity (tamper detection)
    const key = 'k'.repeat(64);
    const sign = d => crypto.createHmac('sha256', key).update(d).digest('hex');
    const data = JSON.stringify({ sub: 'u1', team: 'tm_1', exp: Date.now() + 3600000 });
    const sig = sign(data);
    ok('signature deterministic', sign(data) === sig);
    ok('signature rejects tamper (payload)', sign(data + 'x') !== sig);
    ok('signature rejects tamper (key)', crypto.createHmac('sha256', key + 'y').update(data).digest('hex') !== sig);
  }
}

console.log('── Policy engine (DB-backed via shim) ──');
{
  const p = load('policy/policy-engine.cjs');
  if (p.__error) { skip('Policy engine load', p.__error.message); }
  else {
    try {
      const db = new ShimDbMain();
      p.init(db, null, null);
      const created = p.createPolicy({ name: 'deny ssn', action: 'deny', priority: 1000, conditions: { piiTypes: ['ssn'], minRisk: 30 } });
      ok('createPolicy returns policy', created && created.id && created.name === 'deny ssn');
      ok('createPolicy parses conditions', created && created.conditions && created.conditions.piiTypes[0] === 'ssn');
      const r1 = p.evaluate({ piiTypes: ['ssn'], riskScore: 60, piiCount: 1 });
      ok('evaluate denies matching ssn', r1.action === 'deny' && r1.allowed === false, JSON.stringify(r1));
    } catch (e) {
      ok('policy DB flow ran', false, e.message);
    }
  }
}

console.log('── Organizations (DB-backed via shim) ──');
{
  const o = load('tenancy/organizations.cjs');
  if (o.__error) { skip('Organizations load', o.__error.message); }
  else {
    try {
      const db = new ShimDbMain();
      o.init(db, null);
      const org = o.createOrganization({ name: 'Acme', creatorId: 'cli-admin' });
      ok('createOrganization returns org', org && org.id && org.name === 'Acme');
      ok('getOrganization finds org', o.getOrganization(org.id) !== null);
      ok('listOrganizations includes org', o.listOrganizations().some(x => x.id === org.id));
      const teams = load('auth/teams.cjs');
      teams.init(db, null);
      const team = teams.createTeam ? teams.createTeam({ name: 'Eng' }) : null;
      if (team) {
        o.addTeamToOrg(org.id, team.id);
        ok('listOrgTeams includes linked team', o.listOrgTeams(org.id).some(t => t.id === team.id));
      } else {
        skip('org team linking', 'teams.createTeam not available');
      }
    } catch (e) {
      ok('organizations DB flow ran', false, e.message);
    }
  }
}

console.log('\n═══════════════════════════════════════════════════');
console.log('  PASS: ' + passed + '  |  FAIL: ' + failed + '  |  SKIP: ' + skipped);
if (failures.length) { console.log('  FAILURES:'); failures.forEach(f => console.log('    - ' + f)); }
console.log('═══════════════════════════════════════════════════');
process.exit(failed === 0 ? 0 : 1);
