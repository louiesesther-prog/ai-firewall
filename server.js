#!/usr/bin/env node
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { scrub, scanFile, scanDir, resolveRules, loadConfig, loadPlugins, computeRiskScore, luhnCheck, getCustomFakers, encryptValue, decryptValue, deriveKey, BUILTIN_RULES, COMPLIANCE_PROFILES } = require('./cli.js');
const fs = require('fs');
const { isEnabled } = require('./enterprise/feature-flags.cjs');

// ── Enterprise modules (loaded conditionally) ────────────────────
let enterpriseDb = null;
let audit = null;
let complianceExport = null;
let retention = null;
let webhookDispatcher = null;
let createAuditRoutes = null;
let createWebhookRoutes = null;
let createApiKeyRoutes = null;
let createTeamRoutes = null;
let createScheduledReportRoutes = null;
let scheduledReports = null;
let apiKeys = null;
let teams = null;
let quotas = null;
let responseScanner = null;
let sso = null;
let scim = null;
let policyEngine = null;
let alertService = null;
let shadowMode = null;
let networkAgent = null;
let createSsoRoutes = null;
let createScimRoutes = null;
let createPolicyRoutes = null;
let createAlertRoutes = null;
let createShadowRoutes = null;
let createNetworkRoutes = null;
let rbac = null;
let organizations = null;
let reporting = null;
let marketplace = null;
let createRbacRoutes = null;
let createOrganizationRoutes = null;
let createReportingRoutes = null;
let createMarketplaceRoutes = null;
let enterpriseReady = false;

function initEnterprise(db) {
  try {
    enterpriseDb = db;
    const { initEnterpriseSchema } = require('./enterprise/db.cjs');
    initEnterpriseSchema(db);
    audit = require('./enterprise/audit/audit.cjs');
    audit.init(db);
    complianceExport = require('./enterprise/audit/compliance-export.cjs');
    complianceExport.init(db);
    retention = require('./enterprise/audit/retention.cjs');
    retention.init(db);
    webhookDispatcher = require('./enterprise/integrations/webhooks.cjs');
    webhookDispatcher.init(db);
    scheduledReports = require('./enterprise/audit/scheduled-reports.cjs');
    scheduledReports.init(db, complianceExport, webhookDispatcher);
    apiKeys = require('./enterprise/auth/api-keys.cjs');
    apiKeys.init(db);
    teams = require('./enterprise/auth/teams.cjs');
    teams.init(db);
    quotas = require('./enterprise/auth/quotas.cjs');
    quotas.init(db);
    createAuditRoutes = require('./enterprise/routes/audit-routes.cjs');
    createWebhookRoutes = require('./enterprise/routes/webhook-routes.cjs');
    createApiKeyRoutes = require('./enterprise/routes/api-key-routes.cjs');
    createTeamRoutes = require('./enterprise/routes/team-routes.cjs');
    createScheduledReportRoutes = require('./enterprise/routes/scheduled-report-routes.cjs');
    responseScanner = require('./scanners/response.cjs');
    // Phase 3 modules
    sso = require('./enterprise/identity/sso.cjs');
    scim = require('./enterprise/identity/scim.cjs');
    policyEngine = require('./enterprise/policy/policy-engine.cjs');
    alertService = require('./enterprise/alerts/alerts.cjs');
    shadowMode = require('./enterprise/observability/shadow-mode.cjs');
    networkAgent = require('./enterprise/observability/network-agent.cjs');
    // Phase 3 routes
    createSsoRoutes = require('./enterprise/routes/sso-routes.cjs');
    createScimRoutes = require('./enterprise/routes/scim-routes.cjs');
    createPolicyRoutes = require('./enterprise/routes/policy-routes.cjs');
    createAlertRoutes = require('./enterprise/routes/alert-routes.cjs');
    createShadowRoutes = require('./enterprise/routes/shadow-routes.cjs');
    createNetworkRoutes = require('./enterprise/routes/network-routes.cjs');
    // Phase 4 modules
    rbac = require('./enterprise/auth/rbac.cjs');
    rbac.init(db);
    rbac.ensureSeedPermissions();
    organizations = require('./enterprise/tenancy/organizations.cjs');
    organizations.init(db);
    reporting = require('./enterprise/analytics/advanced-reporting.cjs');
    reporting.init(db, complianceExport, webhookDispatcher);
    marketplace = require('./enterprise/marketplace/marketplace.cjs');
    marketplace.init(db);
    marketplace.seedBuiltins();
    // Phase 4 routes
    createRbacRoutes = require('./enterprise/routes/rbac-routes.cjs');
    createOrganizationRoutes = require('./enterprise/routes/organization-routes.cjs');
    createReportingRoutes = require('./enterprise/routes/reporting-routes.cjs');
    createMarketplaceRoutes = require('./enterprise/routes/marketplace-routes.cjs');
    return true;
  } catch (e) {
    console.warn('[enterprise] Init failed (enterprise features disabled):', e.message);
    return false;
  }
}

const DEFAULT_PORT = 3000;

// ── SIMPLE RATE LIMITER (in-memory, no dependencies) ─────────────
function createRateLimiter({ windowMs = 60000, max = 60 } = {}) {
  const hits = new Map();
  const timer = setInterval(() => {
    const now = Date.now();
    for (const [key, data] of hits) {
      if (now - data.start > windowMs) hits.delete(key);
    }
  }, windowMs);
  if (timer.unref) timer.unref();
  return Object.assign((req, res, next) => {
    const key = req.ip || req.connection.remoteAddress || 'unknown';
    const now = Date.now();
    let entry = hits.get(key);
    if (!entry || now - entry.start > windowMs) {
      entry = { start: now, count: 0 };
      hits.set(key, entry);
    }
    entry.count++;
    res.setHeader('X-RateLimit-Limit', max);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, max - entry.count));
    if (entry.count > max) {
      return res.status(429).json({ error: 'Too many requests. Please try again later.' });
    }
    next();
  }, { _cleanup: () => clearInterval(timer) });
}

// ── API KEY AUTH (optional, via AI_FIREWALL_API_KEY env var) ──────
function createAuthMiddleware(apiKey) {
  if (!apiKey) return (req, res, next) => next();
  const keyBuf = Buffer.from(apiKey);
  return (req, res, next) => {
    if (req.method === 'OPTIONS') return next();
    const provided = req.headers['x-api-key'];
    const provBuf = Buffer.from(provided || '');
    try {
      if (provBuf.length !== keyBuf.length || !crypto.timingSafeEqual(provBuf, keyBuf)) {
        return res.status(401).json({ error: 'Unauthorized. Provide X-API-Key header.' });
      }
    } catch (e) {
      return res.status(401).json({ error: 'Unauthorized. Provide X-API-Key header.' });
    }
    next();
  };
}

function createApp(configOpts = {}) {
  const app = express();
  app.use(express.json({ limit: '1mb' }));
  app.use(express.text({ limit: '1mb', type: 'text/plain' }));

  // ── Security headers ─────────────────────────────────────────
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:");
    res.removeHeader('X-Powered-By');
    next();
  });

  // ── CORS (configurable, default same-origin) ─────────────────
  const allowedOrigins = configOpts.cors
    ? (Array.isArray(configOpts.cors) ? configOpts.cors : [configOpts.cors])
    : [];

  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', allowedOrigins.includes('*') ? '*' : origin);
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-API-Key');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
  });

  // ── Rate limiting ────────────────────────────────────────────
  const limiter = createRateLimiter({ windowMs: 60000, max: configOpts.rateLimit || 60 });
  app.use('/scrub', limiter);
  app.use('/scan', limiter);
  app.use('/diff', limiter);
  app.use('/encrypt', limiter);
  app.use('/decrypt', limiter);
  app.use('/rules/custom', limiter);
  app.use('/scan-response', limiter);
  app.use('/scrub-response', limiter);

  // ── API key auth (optional) ──────────────────────────────────
  const auth = createAuthMiddleware(configOpts.apiKey || process.env.AI_FIREWALL_API_KEY);
  app.use('/scrub', auth);
  app.use('/scan', auth);
  app.use('/diff', auth);
  app.use('/encrypt', auth);
  app.use('/decrypt', auth);
  app.use('/rules/custom', auth);
  app.use('/scan-response', auth);
  app.use('/scrub-response', auth);

  const config = configOpts.config ? loadConfig(configOpts.config) : {};
  const profile = configOpts.profile || 'none';
  const configPluginPaths = (config && config.plugins && Array.isArray(config.plugins)) ? config.plugins : [];
  const plugins = loadPlugins(configPluginPaths);
  const rules = resolveRules(config, profile, plugins.rules);
  const customFakers = Object.assign({}, getCustomFakers(config), plugins.fakers);
  const mode = configOpts.mode || config.mode || 'placeholder';

  app.get('/health', (req, res) => {
    res.json({ status: 'ok', version: require('./package.json').version, uptime: process.uptime() });
  });

  app.get('/rules', (req, res) => {
    res.json({ count: rules.length, profile, customFakersCount: Object.keys(customFakers).length, rules: rules.map(r => ({ id: r.id, name: r.name, label: r.label, confidence: r.conf, luhn: !!r.luhn, custom: !!r.custom })) });
  });

  app.post('/scrub', (req, res) => {
    try {
      const body = typeof req.body === 'string' ? { text: req.body } : (req.body || {});
      const inputText = body.text || body.content || '';
      if (!inputText) return res.status(400).json({ error: 'No text provided. Send JSON { text: "..." } or plain text body.' });

      let activeRules = rules;
      let activeFakers = customFakers;
      if (body.profile || body.customRules) {
        const mergedConfig = {};
        if (config) Object.assign(mergedConfig, config);
        if (body.customRules) mergedConfig.customRules = (mergedConfig.customRules || []).concat(body.customRules);
        activeRules = resolveRules(mergedConfig, body.profile || profile);
        activeFakers = getCustomFakers(mergedConfig);
      }

      const reqMode = body.mode || mode;
      const result = scrub(inputText, { mode: reqMode, rules: activeRules, fakers: activeFakers });
      const riskScore = computeRiskScore(result.matches.map(m => ({ type: m.type, confidence: m.confidence })));

      res.json({
        scrubbed: result.scrubbed,
        matches: result.matches,
        riskScore,
        matchesFound: result.matches.length,
        inputLength: inputText.length,
        mode: reqMode,
        profile: body.profile || profile,
        customRuleCount: (body.customRules || []).length,
      });

      if (tracker && result.matches.length > 0) {
        try {
          tracker.trackScan({
            source: 'api',
            fileType: 'text',
            matches: result.matches.map(m => ({ type: m.type, confidence: m.confidence })),
            riskScore,
            profile: body.profile || profile,
          });
        } catch (e) { /* non-blocking */ }
      }
    } catch (err) {
      console.error('[/scrub] Error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.post('/scan', (req, res) => {
    try {
      const body = req.body || {};
      const inputText = body.text || body.content || '';
      if (!inputText) return res.status(400).json({ error: 'No text provided.' });

      let activeRules = rules;
      if (body.profile || body.customRules) {
        const mergedConfig = {};
        if (config) Object.assign(mergedConfig, config);
        if (body.customRules) mergedConfig.customRules = (mergedConfig.customRules || []).concat(body.customRules);
        activeRules = resolveRules(mergedConfig, body.profile || profile);
      }

      const findings = [];
      for (const rule of activeRules) {
        const regex = new RegExp(rule.regex.source, 'g' + (rule.regex.flags.includes('i') ? 'i' : ''));
        let m;
        while ((m = regex.exec(inputText)) !== null) {
          const raw = m[0];
          let conf = rule.conf;
          if (rule.luhn) {
            const clean = raw.replace(/[-\s]/g, '');
            if (clean.length >= 13 && clean.length <= 19) {
              conf = luhnCheck(clean) ? 0.95 : 0.3;
            }
          }
          const before = inputText.substring(0, m.index);
          const line = (before.match(/\n/g) || []).length + 1;
          const lastNewline = before.lastIndexOf('\n');
          const column = m.index - lastNewline;
          findings.push({ type: rule.label, name: rule.name, match: raw, confidence: conf, line, column });
        }
      }
      findings.sort((a, b) => a.line - b.line || a.column - b.column);

      const riskScore = computeRiskScore(findings.map(m => ({ type: m.type, confidence: m.confidence })));

      res.json({ findings, riskScore, matchesFound: findings.length, inputLength: inputText.length, profile: body.profile || profile });

      if (tracker && findings.length > 0) {
        try {
          tracker.trackScan({
            source: 'api',
            fileType: 'text',
            matches: findings.map(m => ({ type: m.type, confidence: m.confidence })),
            riskScore,
            profile: body.profile || profile,
          });
        } catch (e) { /* non-blocking */ }
      }
    } catch (err) {
      console.error('[/scan] Error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.post('/diff', (req, res) => {
    try {
      const body = req.body || {};
      const inputText = body.text || body.content || '';
      if (!inputText) return res.status(400).json({ error: 'No text provided.' });
      let activeRules = rules;
      let activeFakers = customFakers;
      if (body.profile || body.customRules) {
        const mergedConfig = {};
        if (config) Object.assign(mergedConfig, config);
        if (body.customRules) mergedConfig.customRules = (mergedConfig.customRules || []).concat(body.customRules);
        activeRules = resolveRules(mergedConfig, body.profile || profile);
        activeFakers = getCustomFakers(mergedConfig);
      }
      const result = scrub(inputText, { mode: body.mode || 'placeholder', rules: activeRules, fakers: activeFakers });
      const lines = inputText.split('\n');
      const scrubbedLines = result.scrubbed.split('\n');
      const changes = [];
      for (let i = 0; i < Math.max(lines.length, scrubbedLines.length); i++) {
        if ((lines[i] || '') !== (scrubbedLines[i] || '')) {
          changes.push({ line: i + 1, before: lines[i] || '', after: scrubbedLines[i] || '' });
        }
      }
      res.json({ changes, changesFound: changes.length, matches: result.matches });
    } catch (err) {
      console.error('[/diff] Error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.post('/encrypt', (req, res) => {
    try {
      const body = req.body || {};
      const inputText = body.text || '';
      const passphrase = body.passphrase || '';
      if (!inputText) return res.status(400).json({ error: 'No text provided.' });
      if (!passphrase) return res.status(400).json({ error: 'Passphrase required.' });
      const key = deriveKey(passphrase);
      let activeRules = rules;
      if (body.profile || body.customRules) {
        const mergedConfig = {};
        if (config) Object.assign(mergedConfig, config);
        if (body.customRules) mergedConfig.customRules = (mergedConfig.customRules || []).concat(body.customRules);
        activeRules = resolveRules(mergedConfig, body.profile || profile);
      }
      let result = inputText;
      let count = 0;
      for (const rule of activeRules) {
        const re = new RegExp(rule.regex.source, 'g' + (rule.regex.flags.includes('i') ? 'i' : ''));
        result = result.replace(re, (m) => { count++; return '[ENC:' + encryptValue(m, key) + ']'; });
      }
      res.json({ encrypted: result, itemsEncrypted: count });
    } catch (err) {
      console.error('[/encrypt] Error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.post('/decrypt', (req, res) => {
    try {
      const body = req.body || {};
      const inputText = body.text || '';
      const passphrase = body.passphrase || '';
      if (!inputText) return res.status(400).json({ error: 'No text provided.' });
      if (!passphrase) return res.status(400).json({ error: 'Passphrase required.' });
      let restored = 0;
      const decrypted = inputText.replace(/\[ENC:([^\]]+)\]/g, (_, enc) => {
        const val = decryptValue(enc, passphrase);
        if (val !== null) { restored++; return val; }
        return '[DECRYPT_FAILED]';
      });
      res.json({ decrypted, tokensRestored: restored });
    } catch (err) {
      console.error('[/decrypt] Error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.get('/', (req, res) => {
    const html = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AI Firewall Dashboard</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;padding:20px}
  h1{color:#818cf8;margin-bottom:8px}
  .sub{color:#64748b;font-size:14px;margin-bottom:24px}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:24px}
  .card{background:#1e293b;border-radius:8px;padding:16px;text-align:center}
  .card .num{font-size:32px;font-weight:700;color:#818cf8}
  .card .lbl{font-size:12px;color:#94a3b8;text-transform:uppercase}
  .row{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}
  @media(max-width:768px){.row{grid-template-columns:1fr}}
  .panel{background:#1e293b;border-radius:8px;padding:16px}
  .panel h2{font-size:16px;margin-bottom:12px;color:#94a3b8}
  textarea{width:100%;background:#0f172a;border:1px solid #334155;border-radius:6px;padding:10px;color:#e2e8f0;font-family:monospace;font-size:13px;resize:vertical;min-height:120px}
  textarea:focus{outline:2px solid #6366f1;border-color:transparent}
  select,input{background:#0f172a;border:1px solid #334155;border-radius:6px;padding:8px 10px;color:#e2e8f0;font-size:13px;width:100%;margin-bottom:8px}
  button{background:#6366f1;color:#fff;border:none;border-radius:6px;padding:10px 16px;font-size:14px;cursor:pointer;width:100%;margin-top:4px}
  button:hover{background:#4f46e5}
  pre{background:#0f172a;border-radius:6px;padding:12px;font-size:12px;overflow-x:auto;max-height:300px;overflow-y:auto;margin-top:8px;white-space:pre-wrap;word-break:break-all}
  .badge{display:inline-block;background:#334155;border-radius:10px;padding:2px 8px;font-size:11px;margin:2px;color:#94a3b8}
  .badge.active{background:#6366f1;color:#fff}
  .tabs{display:flex;gap:4px;margin-bottom:12px}
  .tab{padding:8px 16px;border-radius:6px 6px 0 0;cursor:pointer;font-size:13px;background:#334155;color:#94a3b8}
  .tab.active{background:#6366f1;color:#fff}
  .hidden{display:none}
</style></head><body>
<h1>AI Firewall Dashboard</h1>
<div class="sub">Real-time PII detection, scrubbing, encryption, and diff</div>

<div class="cards">
  <div class="card"><div class="num" id="healthStatus">-</div><div class="lbl">Status</div></div>
  <div class="card"><div class="num" id="rulesCount">-</div><div class="lbl">PII Rules</div></div>
  <div class="card"><div class="num" id="uptime">-</div><div class="lbl">Uptime (s)</div></div>
</div>

<div class="tabs">
  <div class="tab active" onclick="switchTab('scrub')">Scrub</div>
  <div class="tab" onclick="switchTab('scan')">Scan</div>
  <div class="tab" onclick="switchTab('diff')">Diff</div>
  <div class="tab" onclick="switchTab('encrypt')">Encrypt</div>
  <div class="tab" onclick="switchTab('decrypt')">Decrypt</div>
</div>

<div id="tab-scrub" class="row">
  <div class="panel">
    <h2>Input</h2>
    <select id="scrubMode"><option value="placeholder">Placeholder</option><option value="realistic">Realistic</option></select>
    <textarea id="scrubInput" placeholder="Paste text with PII here..."></textarea>
    <button onclick="doScrub()">Scrub PII</button>
  </div>
  <div class="panel">
    <h2>Output <span id="scrubCount" class="badge">0 matches</span></h2>
    <pre id="scrubOutput">Results will appear here...</pre>
  </div>
</div>

<div id="tab-scan" class="row hidden">
  <div class="panel">
    <h2>Text to Scan</h2>
    <textarea id="scanInput" placeholder="Paste text to scan for PII..."></textarea>
    <button onclick="doScan()">Find PII</button>
  </div>
  <div class="panel">
    <h2>Findings <span id="scanCount" class="badge">0</span></h2>
    <pre id="scanOutput">Scan results will appear here...</pre>
  </div>
</div>

<div id="tab-diff" class="row hidden">
  <div class="panel">
    <h2>Original</h2>
    <textarea id="diffInput" placeholder="Paste text to diff..."></textarea>
    <button onclick="doDiff()">Show Diff</button>
  </div>
  <div class="panel">
    <h2>Changes <span id="diffCount" class="badge">0</span></h2>
    <pre id="diffOutput">Diff results will appear here...</pre>
  </div>
</div>

<div id="tab-encrypt" class="row hidden">
  <div class="panel">
    <h2>Text with PII</h2>
    <input type="password" id="encryptKey" placeholder="Encryption passphrase">
    <textarea id="encryptInput" placeholder="Paste text with PII to encrypt..."></textarea>
    <button onclick="doEncrypt()">Encrypt PII</button>
  </div>
  <div class="panel">
    <h2>Encrypted <span id="encryptCount" class="badge">0 items</span></h2>
    <pre id="encryptOutput">Encrypted text will appear here...</pre>
  </div>
</div>

<div id="tab-decrypt" class="row hidden">
  <div class="panel">
    <h2>Encrypted Text</h2>
    <input type="password" id="decryptKey" placeholder="Decryption passphrase">
    <textarea id="decryptInput" placeholder="Paste text with [ENC:...] tokens..."></textarea>
    <button onclick="doDecrypt()">Decrypt</button>
  </div>
  <div class="panel">
    <h2>Decrypted <span id="decryptCount" class="badge">0 tokens</span></h2>
    <pre id="decryptOutput">Decrypted text will appear here...</pre>
  </div>
</div>

<script>
async function api(path, data) {
  const r = await fetch(path, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data) });
  return r.json();
}
async function loadHealth() {
  try {
    const r = await fetch('/health'); const d = await r.json();
    document.getElementById('healthStatus').textContent = d.status || 'err';
    document.getElementById('uptime').textContent = Math.floor(d.uptime || 0);
  } catch(e) { document.getElementById('healthStatus').textContent = 'offline'; }
  try {
    const r = await fetch('/rules'); const d = await r.json();
    document.getElementById('rulesCount').textContent = d.count || 0;
  } catch(e) {}
}
async function doScrub() {
  const text = document.getElementById('scrubInput').value;
  const mode = document.getElementById('scrubMode').value;
  if (!text) return;
  const r = await api('/scrub', { text, mode });
  document.getElementById('scrubOutput').textContent = r.scrubbed || r.error || 'Error';
  document.getElementById('scrubCount').textContent = (r.matchesFound || 0) + ' matches';
}
async function doScan() {
  const text = document.getElementById('scanInput').value;
  if (!text) return;
  const r = await api('/scan', { text });
  const findings = r.findings || [];
  let out = findings.length === 0 ? 'No PII detected.' : '';
  for (const m of findings) out += 'Ln ' + m.line + ' Col ' + m.column + ' [' + m.type + '] ' + m.match + ' (conf: ' + Math.round(m.confidence*100) + '%)\\n';
  document.getElementById('scanOutput').textContent = out || 'No PII detected.';
  document.getElementById('scanCount').textContent = findings.length;
}
async function doDiff() {
  const text = document.getElementById('diffInput').value;
  if (!text) return;
  const r = await api('/diff', { text });
  const changes = r.changes || [];
  let out = changes.length === 0 ? 'No changes.' : '';
  for (const c of changes) out += 'Ln ' + c.line + ':\\n- ' + c.before.substring(0,80) + '\\n+ ' + c.after.substring(0,80) + '\\n\\n';
  document.getElementById('diffOutput').textContent = out || 'No changes.';
  document.getElementById('diffCount').textContent = changes.length + ' changes';
}
async function doEncrypt() {
  const text = document.getElementById('encryptInput').value;
  const key = document.getElementById('encryptKey').value;
  if (!text || !key) return;
  const r = await api('/encrypt', { text, passphrase: key });
  document.getElementById('encryptOutput').textContent = r.encrypted || r.error || 'Error';
  document.getElementById('encryptCount').textContent = (r.itemsEncrypted || 0) + ' items';
}
async function doDecrypt() {
  const text = document.getElementById('decryptInput').value;
  const key = document.getElementById('decryptKey').value;
  if (!text || !key) return;
  const r = await api('/decrypt', { text, passphrase: key });
  document.getElementById('decryptOutput').textContent = r.decrypted || r.error || 'Error';
  document.getElementById('decryptCount').textContent = (r.tokensRestored || 0) + ' tokens';
}
function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('[id^="tab-"]').forEach(t => t.classList.add('hidden'));
  document.querySelector('.tab[onclick*="' + name + '"]').classList.add('active');
  document.getElementById('tab-' + name).classList.remove('hidden');
}
loadHealth();
setInterval(loadHealth, 5000);
</script></body></html>`;
    res.type('html').send(html);
  });

  app.post('/rules/custom', (req, res) => {
    try {
      const body = req.body || {};
      if (!body.rules || !Array.isArray(body.rules)) {
        return res.status(400).json({ error: 'Send JSON { rules: [...] } with custom rule definitions.' });
      }
      const mergedConfig = {};
      if (config) Object.assign(mergedConfig, config);
      mergedConfig.customRules = body.rules;
      const testRules = resolveRules(mergedConfig, body.profile || 'none');
      const validated = testRules.filter(r => r.custom).map(r => ({ id: r.id, name: r.name, label: r.label, confidence: r.conf }));
      res.json({ success: true, customRulesLoaded: validated.length, rules: validated });
    } catch (err) {
      console.error('[/rules/custom] Error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ── ANALYTICS ENDPOINTS ──────────────────────────────────────
  let tracker = null;
  let queries = null;
  let analyticsDbPath = null;

  function initAnalytics(dbPath) {
    try {
      tracker = require('./analytics/tracker.cjs');
      queries = require('./analytics/queries.cjs');
      analyticsDbPath = dbPath || null;
      const { getDb } = require('./analytics/db.cjs');
      getDb(dbPath);
      return true;
    } catch (e) {
      console.warn('Analytics unavailable: ' + e.message);
      return false;
    }
  }

  if (configOpts.analytics) {
    initAnalytics(configOpts.analyticsDb);
  }

  app.get('/analytics', (req, res) => {
    try {
      const htmlPath = path.join(__dirname, 'analytics', 'dashboard.html');
      const html = fs.readFileSync(htmlPath, 'utf8');
      res.type('html').send(html);
    } catch (e) {
      res.status(500).json({ error: 'Dashboard file not found' });
    }
  });

  app.get('/api/analytics/summary', (req, res) => {
    if (!queries) return res.status(503).json({ error: 'Analytics not enabled. Start with --analytics flag.' });
    try { res.json(queries.getSummary()); }
    catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.get('/api/analytics/trend', (req, res) => {
    if (!queries) return res.status(503).json({ error: 'Analytics not enabled.' });
    const days = parseInt(req.query.days, 10) || 30;
    try { res.json(queries.getTrendData(days)); }
    catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.get('/api/analytics/types', (req, res) => {
    if (!queries) return res.status(503).json({ error: 'Analytics not enabled.' });
    const limit = parseInt(req.query.limit, 10) || 10;
    try { res.json(queries.getTopPIITypes(limit)); }
    catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.get('/api/analytics/risk', (req, res) => {
    if (!queries) return res.status(503).json({ error: 'Analytics not enabled.' });
    try { res.json(queries.getRiskDistribution()); }
    catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.get('/api/analytics/recent', (req, res) => {
    if (!queries) return res.status(503).json({ error: 'Analytics not enabled.' });
    const limit = parseInt(req.query.limit, 10) || 20;
    try { res.json(queries.getRecentScans(limit)); }
    catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── ENTERPRISE INIT ──────────────────────────────────────────
  function initEnterpriseDB() {
    try {
      const { getDb: getAnalyticsDb } = require('./analytics/db.cjs');
      const db = getAnalyticsDb(configOpts.analyticsDb);
      enterpriseReady = initEnterprise(db);
    } catch (e) {
      console.warn('[enterprise] Could not initialize:', e.message);
    }
  }
  initEnterpriseDB();

  // Wire webhook dispatcher into tracker for scan events
  if (tracker && webhookDispatcher) {
    tracker.setWebhookDispatcher(webhookDispatcher);
  }

  // ── RESPONSE SCANNING ENDPOINTS ──────────────────────────────
  app.post('/scan-response', (req, res) => {
    try {
      const body = typeof req.body === 'string' ? { text: req.body } : (req.body || {});
      const inputText = body.text || body.content || '';
      if (!inputText) return res.status(400).json({ error: 'No text provided.' });

      const result = responseScanner
        ? responseScanner.scanResponse(inputText, {
            service: body.service || 'unknown',
            threshold: body.threshold || 0.65,
            profile: body.profile || 'none',
            rules: rules,
          })
        : { findings: [], riskScore: 0, actionTaken: 'none', service: body.service || 'unknown' };

      res.json(result);

      if (audit) {
        try {
          audit.logResponseScan({
            userId: req.headers['x-user-id'] || null,
            teamId: req.headers['x-team-id'] || null,
            piiTypes: result.findings.map(f => f.type),
            riskScore: result.riskScore,
            actionTaken: result.actionTaken,
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'] || null,
            metadata: { service: result.service, inputLength: inputText.length },
          });
        } catch (e) { /* non-blocking */ }
      }

      if (tracker && result.findings.length > 0) {
        try {
          tracker.trackScan({
            source: 'api:response',
            fileType: 'ai_response',
            matches: result.findings.map(f => ({ type: f.type, confidence: f.confidence })),
            riskScore: result.riskScore,
            profile: body.profile || 'none',
          });
        } catch (e) { /* non-blocking */ }
      }
    } catch (err) {
      console.error('[/scan-response] Error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.post('/scrub-response', (req, res) => {
    try {
      const body = typeof req.body === 'string' ? { text: req.body } : (req.body || {});
      const inputText = body.text || body.content || '';
      if (!inputText) return res.status(400).json({ error: 'No text provided.' });

      const result = responseScanner
        ? responseScanner.scrubResponse(inputText, {
            mode: body.mode || 'placeholder',
            profile: body.profile || 'none',
            rules: rules,
            fakers: customFakers,
          })
        : { scrubbed: inputText, matches: [], actionTaken: 'none' };

      res.json(result);

      if (audit) {
        try {
          audit.logScrub({
            userId: req.headers['x-user-id'] || null,
            teamId: req.headers['x-team-id'] || null,
            piiTypes: result.matches.map(m => m.type),
            riskScore: computeRiskScore(result.matches.map(m => ({ type: m.type, confidence: m.confidence }))),
            actionTaken: result.actionTaken,
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'] || null,
            metadata: { source: 'response_scrub', inputLength: inputText.length },
          });
        } catch (e) { /* non-blocking */ }
      }
    } catch (err) {
      console.error('[/scrub-response] Error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ── ENTERPRISE ROUTES (gated per-module via feature flags) ────
  if (enterpriseReady && createAuditRoutes && isEnabled('audit')) {
    app.use('/audit', createAuditRoutes(enterpriseDb));
  }
  if (enterpriseReady && createWebhookRoutes && isEnabled('webhooks')) {
    app.use('/webhooks', createWebhookRoutes(enterpriseDb));
  }
  if (enterpriseReady && createApiKeyRoutes && isEnabled('apiKeys')) {
    app.use('/api-keys', createApiKeyRoutes(enterpriseDb));
  }
  if (enterpriseReady && createTeamRoutes && isEnabled('teams')) {
    app.use('/teams', createTeamRoutes(enterpriseDb));
  }
  if (enterpriseReady && createScheduledReportRoutes && isEnabled('scheduled')) {
    app.use('/scheduled-reports', createScheduledReportRoutes(enterpriseDb, complianceExport, webhookDispatcher));
  }
  if (enterpriseReady && createSsoRoutes && isEnabled('sso')) {
    app.use('/sso', createSsoRoutes(enterpriseDb));
  }
  if (enterpriseReady && createScimRoutes && isEnabled('scim')) {
    app.use('/scim', createScimRoutes(enterpriseDb));
  }
  if (enterpriseReady && createPolicyRoutes && isEnabled('policy')) {
    app.use('/policies', createPolicyRoutes(enterpriseDb));
  }
  if (enterpriseReady && createAlertRoutes && isEnabled('alerts')) {
    app.use('/alerts', createAlertRoutes(enterpriseDb, webhookDispatcher));
  }
  if (enterpriseReady && createShadowRoutes && isEnabled('shadow')) {
    app.use('/shadow', createShadowRoutes(enterpriseDb));
  }
  if (enterpriseReady && createNetworkRoutes && isEnabled('networkAgent')) {
    app.use('/network', createNetworkRoutes(enterpriseDb));
  }
  if (enterpriseReady && createRbacRoutes && isEnabled('rbac')) {
    app.use('/rbac', createRbacRoutes(enterpriseDb));
  }
  if (enterpriseReady && createOrganizationRoutes && isEnabled('tenancy')) {
    app.use('/orgs', createOrganizationRoutes(enterpriseDb));
  }
  if (enterpriseReady && createReportingRoutes && isEnabled('reporting')) {
    app.use('/reports', createReportingRoutes(enterpriseDb, webhookDispatcher));
  }
  if (enterpriseReady && createMarketplaceRoutes && isEnabled('marketplace')) {
    app.use('/marketplace', createMarketplaceRoutes(enterpriseDb));
  }

  // ── ENTERPRISE DASHBOARD ──────────────────────────────────────
  app.get('/enterprise', (req, res) => {
    try {
      const htmlPath = path.join(__dirname, 'enterprise', 'dashboard', 'index.html');
      const html = fs.readFileSync(htmlPath, 'utf8');
      res.type('html').send(html);
    } catch (e) {
      res.status(404).json({ error: 'Enterprise dashboard not found' });
    }
  });

  // ── AUDIT MIDDLEWARE ─────────────────────────────────────────
  if (audit) {
    app.use((req, res, next) => {
      const start = Date.now();
      const originalJson = res.json.bind(res);
      res.json = function(body) {
        const duration = Date.now() - start;
        if (req.method === 'POST' && req.path.startsWith('/scrub') && body && body.matchesFound > 0) {
          try {
            audit.logScrub({
              userId: req.headers['x-user-id'] || null,
              teamId: req.headers['x-team-id'] || null,
              action: 'scrub',
              piiTypes: (body.matches || []).map(m => m.type),
              riskScore: body.riskScore || 0,
              actionTaken: 'scrubbed',
              ipAddress: req.ip,
              userAgent: req.headers['user-agent'] || null,
              metadata: { endpoint: req.path, duration: duration },
            });
          } catch (e) { /* non-blocking */ }
        }
        if (req.method === 'POST' && req.path.startsWith('/scan') && body && body.matchesFound > 0) {
          try {
            audit.logScan({
              userId: req.headers['x-user-id'] || null,
              teamId: req.headers['x-team-id'] || null,
              action: 'scan',
              piiTypes: (body.findings || body.matches || []).map(m => m.type),
              riskScore: body.riskScore || 0,
              actionTaken: 'detected',
              ipAddress: req.ip,
              userAgent: req.headers['user-agent'] || null,
              metadata: { endpoint: req.path, duration: duration },
            });
          } catch (e) { /* non-blocking */ }
        }
        return originalJson(body);
      };
      next();
    });
  }

  // ── FILE UPLOAD ENDPOINT ──────────────────────────────────────
  app.use('/scan-file', (req, res, next) => {
    if (req.method !== 'POST' || !(req.headers['content-type'] || '').includes('multipart/form-data')) return next();
    const ct = req.headers['content-type'] || '';
    const boundaryMatch = ct.match(/boundary=(.+)/i);
    if (!boundaryMatch) return res.status(400).json({ error: 'Missing multipart boundary.' });
    const boundary = '--' + boundaryMatch[1].trim();

    const chunks = [];
    const MAX_UPLOAD = 5 * 1024 * 1024; // 5MB
    let totalSize = 0;
    let tooLarge = false;
    req.on('data', (chunk) => {
      if (tooLarge) return;
      totalSize += chunk.length;
      if (totalSize > MAX_UPLOAD) {
        tooLarge = true;
        req.destroy();
        return res.status(413).json({ error: 'File too large. Maximum 5MB.' });
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (tooLarge) return;
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        const parts = raw.split(boundary).filter(p => p.trim() && p.trim() !== '--');
        let filename = 'uploaded.txt';
        let textContent = '';

        for (const part of parts) {
          const headerEnd = part.indexOf('\r\n\r\n');
          if (headerEnd === -1) continue;
          const headers = part.substring(0, headerEnd);
          const body = part.substring(headerEnd + 4);
          const cleaned = body.replace(/\r\n$/, '');
          const fnMatch = headers.match(/filename="([^"]+)"/i);
          const nameMatch = headers.match(/name="([^"]+)"/i);
          if (fnMatch) filename = fnMatch[1];
          if (nameMatch && (nameMatch[1] === 'text' || nameMatch[1] === 'content')) {
            textContent = cleaned;
          } else if (!textContent) {
            textContent = cleaned;
          }
        }

        if (!textContent.trim()) return res.status(400).json({ error: 'No text content found in upload.' });

        const activeProfile = (req.body && req.body.profile) || profile;
        const activeRules = (req.body && req.body.profile)
          ? resolveRules(Object.assign({}, config, { profile: req.body.profile }), req.body.profile)
          : rules;

        const findings = [];
        for (const rule of activeRules) {
          const regex = new RegExp(rule.regex.source, 'g' + (rule.regex.flags.includes('i') ? 'i' : ''));
          let m;
          while ((m = regex.exec(textContent)) !== null) {
            const raw = m[0];
            let conf = rule.conf;
            if (rule.luhn) {
              const clean = raw.replace(/[-\s]/g, '');
              if (clean.length >= 13 && clean.length <= 19) {
                conf = luhnCheck(clean) ? 0.95 : 0.3;
              }
            }
            const before = textContent.substring(0, m.index);
            const line = (before.match(/\n/g) || []).length + 1;
            const lastNewline = before.lastIndexOf('\n');
            const column = m.index - lastNewline;
            findings.push({ type: rule.label, name: rule.name, match: raw, confidence: conf, line, column });
          }
        }
        findings.sort((a, b) => a.line - b.line || a.column - b.column);

        const riskScore = computeRiskScore(findings.map(f => ({ type: f.type, confidence: f.confidence })));

        res.json({
          filename,
          findings,
          riskScore,
          matchesFound: findings.length,
          inputLength: textContent.length,
          profile: activeProfile,
        });

        if (tracker && findings.length > 0) {
          try {
            tracker.trackScan({
              source: 'api',
              fileType: 'file-upload',
              fileName: filename,
              matches: findings.map(f => ({ type: f.type, confidence: f.confidence })),
              riskScore,
              profile: activeProfile,
            });
          } catch (e) { /* non-blocking */ }
        }
      } catch (err) {
        res.status(500).json({ error: 'Failed to parse multipart data.' });
      }
    });
    req.on('error', () => res.status(500).json({ error: 'Upload failed.' }));
  });

  // ── 404 handler ──────────────────────────────────────────────
  app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  // ── Global error handler ─────────────────────────────────────
  app.use((err, req, res, _next) => {
    console.error('Unhandled error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}

function startServer(port, configOpts, callback) {
  const app = createApp(configOpts);
  const server = app.listen(port, () => {
    const addr = server.address();
    console.log('AI Firewall API server running on http://localhost:' + addr.port);
    console.log('Profile: ' + (configOpts.profile || 'none') + ' | Rules: ' + BUILTIN_RULES.length);
    console.log('Endpoints:');
    console.log('  GET  /          - Web dashboard');
    console.log('  GET  /health    - Health check');
    console.log('  GET  /rules     - List PII rules');
    console.log('  POST /scrub     - Scrub PII from text');
    console.log('  POST /scan      - Scan text for PII');
    console.log('  POST /diff      - Show before/after diff');
    console.log('  POST /encrypt   - Encrypt PII with passphrase');
    console.log('  POST /decrypt   - Decrypt [ENC:...] tokens');
    console.log('  POST /scan-response  - Scan AI response for PII');
    console.log('  POST /scrub-response - Scrub PII from AI response');
    console.log('  POST /rules/custom - Validate custom rules');
    if (enterpriseReady) {
      console.log('  GET  /enterprise         - Enterprise dashboard');
      console.log('  GET  /audit/events       - Audit trail events');
      console.log('  POST /audit/export       - Generate compliance report');
      console.log('  GET  /api-keys           - List API keys');
      console.log('  POST /api-keys           - Generate API key');
      console.log('  GET  /teams              - List teams');
      console.log('  POST /teams              - Create team');
      console.log('  GET  /scheduled-reports  - List report schedules');
      console.log('  GET  /webhooks           - List webhooks');
      console.log('  POST /webhooks           - Create webhook');
      console.log('  POST /sso/token          - Issue SSO token');
      console.log('  POST /sso/verify         - Validate SSO token');
      console.log('  GET  /sso/sessions       - List SSO sessions');
      console.log('  GET  /scim/v2/Users      - SCIM users (provisioning)');
      console.log('  GET  /scim/v2/Groups     - SCIM groups');
      console.log('  GET  /policies           - List data guardrails');
      console.log('  POST /policies/evaluate  - Evaluate content vs policies');
      console.log('  GET  /alerts             - List alerts');
      console.log('  GET  /alerts/rules       - List alert rules');
      console.log('  GET  /shadow/events      - Shadow mode events');
      console.log('  GET  /shadow/discover    - Shadow AI discovery');
      console.log('  GET  /network/events     - Network agent events');
      console.log('  POST /network/connection - Record network connection');
      console.log('  GET  /rbac              - RBAC / permissions');
      console.log('  GET  /orgs              - Multi-tenant organizations');
      console.log('  GET  /reports/dashboard - Analytics dashboard');
      console.log('  POST /reports/run       - Generate summary report');
      console.log('  GET  /marketplace/packs - Rule packs');
      console.log('  GET  /marketplace/templates - Policy templates');
    }
    if (configOpts.analytics) {
      console.log('  GET  /analytics - Analytics dashboard');
      console.log('  GET  /api/analytics/* - Analytics API');
    }
    if (configOpts.apiKey || process.env.AI_FIREWALL_API_KEY) {
      console.log('  Auth: API key required (X-API-Key header)');
    }
    console.log('Press Ctrl+C to stop.');
    if (callback) callback(server);
  });
  return server;
}

if (require.main === module) {
  process.on('uncaughtException', (err) => { console.error('Uncaught exception:', err.message || err); process.exit(1); });
  process.on('unhandledRejection', (err) => { console.error('Unhandled rejection:', err && err.message ? err.message : err); });
  const args = process.argv.slice(2);
  let port = parseInt(process.env.PORT, 10) || DEFAULT_PORT;
  let configPath = null;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port' || args[i] === '-p') {
      const p = parseInt(args[++i], 10);
      port = isNaN(p) || p < 1 || p > 65535 ? DEFAULT_PORT : p;
    }
    if (args[i] === '--config' || args[i] === '-c') configPath = args[++i];
  }
  startServer(port, { config: configPath });
}

module.exports = { createApp, startServer };
