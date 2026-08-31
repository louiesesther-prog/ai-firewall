// ── Rule & Policy Marketplace ────────────────────────────────────────
// Installable rule packs (bundles of PII detection rules) and policy
// templates (ready-to-create guardrail policies) for common compliance
// targets. Packs can be imported (bulk-add rules via CLI/API) or exported.

var _db = null;
var _cli = null;   // reference to cli.js rule helpers (createRule etc.) for installing packs

function init(database, cliRef) {
  _db = database;
  _cli = cliRef;
}

// ── Built-in rule packs ──────────────────────────────────────────────
// Each pack defines a bundle of rule configurations. These mirror the
// detection rules exposed by the core scanner.

var BUILTIN_PACKS = [
  {
    slug: 'hipaa-phi',
    name: 'HIPAA PHI Essentials',
    description: 'Core protected health information: SSN, phone, email, address, DOB, patient IDs.',
    category: 'hipaa',
    author: 'AI Firewall',
    version: '1.0.0',
    rules: [
      { ruleId: 'ssn', name: 'Social Security Number', type: 'ssn' },
      { ruleId: 'phone', name: 'Phone Number', type: 'phone' },
      { ruleId: 'email', name: 'Email Address', type: 'email' },
      { ruleId: 'address', name: 'Street Address', type: 'address' },
      { ruleId: 'dob', name: 'Date of Birth', type: 'dob' },
    ],
  },
  {
    slug: 'pci-cardholder',
    name: 'PCI Cardholder Data',
    description: 'Payment card data: card numbers, CVV, expiration, account identifiers.',
    category: 'pci',
    author: 'AI Firewall',
    version: '1.0.0',
    rules: [
      { ruleId: 'credit-card', name: 'Credit Card Number', type: 'credit-card' },
      { ruleId: 'cvv', name: 'CVV / Security Code', type: 'cvv' },
      { ruleId: 'card-expiry', name: 'Card Expiration', type: 'card-expiry' },
      { ruleId: 'iban', name: 'IBAN', type: 'iban' },
    ],
  },
  {
    slug: 'gdpr-personal',
    name: 'GDPR Personal Data',
    description: 'Personal data under GDPR Art. 4: names, contact, IDs, and location data.',
    category: 'gdpr',
    author: 'AI Firewall',
    version: '1.0.0',
    rules: [
      { ruleId: 'email', name: 'Email Address', type: 'email' },
      { ruleId: 'phone', name: 'Phone Number', type: 'phone' },
      { ruleId: 'full-name', name: 'Full Name', type: 'full-name' },
      { ruleId: 'ip', name: 'IP Address', type: 'ip' },
      { ruleId: 'address', name: 'Street Address', type: 'address' },
    ],
  },
  {
    slug: 'ccpa-consumer',
    name: 'CCPA Consumer Info',
    description: 'California consumer personal information: identifiers and protected classifications.',
    category: 'ccpa',
    author: 'AI Firewall',
    version: '1.0.0',
    rules: [
      { ruleId: 'email', name: 'Email Address', type: 'email' },
      { ruleId: 'address', name: 'Postal Address', type: 'address' },
      { ruleId: 'phone', name: 'Phone Number', type: 'phone' },
      { ruleId: 'dob', name: 'Date of Birth', type: 'dob' },
      { ruleId: 'ip', name: 'IP Address', type: 'ip' },
    ],
  },
  {
    slug: 'soc2-security',
    name: 'SOC 2 Security',
    description: 'Security-relevant identifiers: credentials, keys, tokens, session identifiers.',
    category: 'soc2',
    author: 'AI Firewall',
    version: '1.0.0',
    rules: [
      { ruleId: 'credential', name: 'Credentials / Password', type: 'credential' },
      { ruleId: 'api-key', name: 'API Key', type: 'api-key' },
      { ruleId: 'token', name: 'Session Token', type: 'token' },
      { ruleId: 'jwt', name: 'JWT', type: 'jwt' },
    ],
  },
];

// ── Built-in policy templates ────────────────────────────────────────
var BUILTIN_TEMPLATES = [
  {
    slug: 'block-pii-outbound',
    name: 'Block PII in Outbound',
    description: 'Deny any outbound content containing high-sensitivity PII (SSN, credit card, credentials).',
    category: 'data-loss',
    action: 'deny',
    scope: 'outbound',
    conditions: { piiTypes: ['ssn', 'credit-card', 'credential'], matchedAny: true },
  },
  {
    slug: 'redact-personal-ai',
    name: 'Redact Personal Data for AI',
    description: 'Redact email/phone/address before sending prompts to AI services.',
    category: 'compliance',
    action: 'redact',
    scope: 'prompt',
    conditions: { piiTypes: ['email', 'phone', 'address'], matchedAny: true },
  },
  {
    slug: 'block-sensitive-inbound',
    name: 'Block Sensitive Inbound',
    description: 'Quarantine inbound content containing payment or identity data.',
    category: 'data-loss',
    action: 'quarantine',
    scope: 'inbound',
    conditions: { piiTypes: ['credit-card', 'ssn'], matchedAny: true },
  },
  {
    slug: 'block-scrubbed-upload',
    name: 'Block Unscrubbed Upload',
    description: 'Deny uploads that would leak >3 PII instances.',
    category: 'ai-guardrails',
    action: 'deny',
    scope: 'upload',
    conditions: { detectionCount: 4 },
  },
];

var _seeded = false;

// Seed built-in packs/templates into DB on first init
function seedBuiltins() {
  if (!_db || _seeded) return;
  _seeded = true;

  for (var i = 0; i < BUILTIN_PACKS.length; i++) {
    var pack = BUILTIN_PACKS[i];
    _db.run(
      `INSERT OR IGNORE INTO rule_packs (id, slug, name, description, version, category, author, license, rules_count)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'MIT', ?)`,
      [packSlugToId(pack.slug), pack.slug, pack.name, pack.description, pack.version,
       pack.category, pack.author, pack.rules.length]
    );
    // Insert rules
    for (var r = 0; r < pack.rules.length; r++) {
      _db.run(
        `INSERT OR IGNORE INTO rule_pack_rules (pack_id, rule_id, rule_json) VALUES (?, ?, ?)`,
        [packSlugToId(pack.slug), pack.rules[r].ruleId, JSON.stringify(pack.rules[r])]
      );
    }
  }

  for (var t = 0; t < BUILTIN_TEMPLATES.length; t++) {
    var tmpl = BUILTIN_TEMPLATES[t];
    _db.run(
      `INSERT OR IGNORE INTO policy_templates (id, slug, name, description, category, action, conditions, scope)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ['pt_' + tmpl.slug.replace(/-/g, '_'), tmpl.slug, tmpl.name, tmpl.description, tmpl.category,
       tmpl.action, JSON.stringify(tmpl.conditions || {}), tmpl.scope || '*']
    );
  }
}

function packSlugToId(slug) {
  return 'rp_' + slug.replace(/-/g, '_');
}

// ── Rule packs ───────────────────────────────────────────────────────

function listPacks(options) {
  if (!_db) return [];
  options = options || {};
  var where = [];
  var params = [];
  if (options.category) { where.push('category = ?'); params.push(options.category); }
  if (options.installed !== undefined) { where.push('installed = ?'); params.push(options.installed ? 1 : 0); }

  var sql = 'SELECT id, slug, name, description, version, category, author, license, enabled, installed, rules_count FROM rule_packs';
  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  sql += ' ORDER BY category ASC, name ASC';

  var stmt = _db.prepare(sql);
  if (params.length) stmt.bind(params);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function getPack(id) {
  var stmt = _db.prepare('SELECT * FROM rule_packs WHERE id = ?');
  stmt.bind([id]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  if (!row) return null;
  row.rules = getPackRules(id);
  return row;
}

function getPackBySlug(slug) {
  var stmt = _db.prepare('SELECT * FROM rule_packs WHERE slug = ?');
  stmt.bind([slug]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  if (!row) return null;
  row.rules = getPackRules(row.id);
  return row;
}

function getPackRules(packId) {
  var stmt = _db.prepare('SELECT rule_id, rule_json FROM rule_pack_rules WHERE pack_id = ?');
  stmt.bind([packId]);
  var rows = [];
  while (stmt.step()) {
    var r = stmt.getAsObject();
    try { r.rule = JSON.parse(r.rule_json); } catch (e) { r.rule = null; }
    rows.push(r);
  }
  stmt.free();
  return rows;
}

// Install a pack: mark installed + (optionally) register its rules in core
function installPack(idOrSlug, options) {
  var pack = getPack(idOrSlug) || getPackBySlug(idOrSlug);
  if (!pack) return { error: 'Pack not found' };
  _db.run('UPDATE rule_packs SET installed = 1, updated_at = datetime("now") WHERE id = ?', [pack.id]);

  var rules = getPackRules(pack.id);
  var installed = [];
  if (_cli && rules.length) {
    for (var i = 0; i < rules.length; i++) {
      try {
        // Register the rule through core rule factory if available
        if (_cli.createRule) {
          _cli.createRule(rules[i].rule);
          installed.push(rules[i].rule_id);
        }
      } catch (e) { /* rule may already exist */ }
    }
  }
  return { installed: true, packId: pack.id, rulesInstalled: installed.length };
}

function uninstallPack(idOrSlug) {
  var pack = getPack(idOrSlug) || getPackBySlug(idOrSlug);
  if (!pack) return { error: 'Pack not found' };
  _db.run('UPDATE rule_packs SET installed = 0, updated_at = datetime("now") WHERE id = ?', [pack.id]);
  return { uninstalled: true, packId: pack.id };
}

// Import a custom pack (from JSON)
function importPack(packJson) {
  var pack = typeof packJson === 'string' ? JSON.parse(packJson) : packJson;
  if (!pack || !pack.slug) return { error: 'Invalid pack: slug required' };
  var id = packSlugToId(pack.slug);

  _db.run(
    `INSERT OR REPLACE INTO rule_packs (id, slug, name, description, version, category, author, license, rules_count, installed)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
    [id, pack.slug, pack.name || pack.slug, pack.description || null, pack.version || '1.0.0',
     pack.category || 'custom', pack.author || 'custom', pack.license || 'custom', (pack.rules || []).length]
  );

  _db.run('DELETE FROM rule_pack_rules WHERE pack_id = ?', [id]);
  for (var i = 0; i < (pack.rules || []).length; i++) {
    var rule = pack.rules[i];
    _db.run('INSERT INTO rule_pack_rules (pack_id, rule_id, rule_json) VALUES (?, ?, ?)',
      [id, rule.ruleId || rule.id || ('r' + i), JSON.stringify(rule)]);
  }
  return getPack(id);
}

function exportPack(idOrSlug) {
  var pack = getPack(idOrSlug) || getPackBySlug(idOrSlug);
  if (!pack) return null;
  return {
    slug: pack.slug, name: pack.name, description: pack.description,
    version: pack.version, category: pack.category, author: pack.author,
    license: pack.license,
    rules: pack.rules.map(function(r) { return r.rule || { ruleId: r.rule_id }; }),
  };
}

// ── Policy templates ─────────────────────────────────────────────────

function listTemplates(category) {
  var where = [];
  var params = [];
  if (category) { where.push('category = ?'); params.push(category); }
  var sql = 'SELECT * FROM policy_templates';
  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  sql += ' ORDER BY category ASC, name ASC';
  var stmt = _db.prepare(sql);
  if (params.length) stmt.bind(params);
  var rows = [];
  while (stmt.step()) {
    var r = stmt.getAsObject();
    try { r.conditions = JSON.parse(r.conditions || '{}'); } catch (e) { r.conditions = {}; }
    rows.push(r);
  }
  stmt.free();
  return rows;
}

function getTemplate(idOrSlug) {
  var stmt = _db.prepare('SELECT * FROM policy_templates WHERE id = ? OR slug = ?');
  stmt.bind([idOrSlug, idOrSlug]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  if (!row) return null;
  try { row.conditions = JSON.parse(row.conditions || '{}'); } catch (e) { row.conditions = {}; }
  return row;
}

// Convert a template into a live policy (via policy-engine createPolicy)
function applyTemplate(idOrSlug, policyEngine, options) {
  var t = getTemplate(idOrSlug);
  if (!t) return { error: 'Template not found' };
  if (!policyEngine) return { error: 'Policy engine unavailable' };
  var p = policyEngine.createPolicy({
    name: (options && options.name) || t.name,
    description: t.description,
    teamId: (options && options.teamId) || null,
    action: t.action,
    scope: t.scope || '*',
    conditions: t.conditions || {},
    priority: (options && options.priority) || 500,
  });
  return { applied: true, policy: p };
}

module.exports = {
  init,
  listPacks,
  getPack,
  getPackBySlug,
  installPack,
  uninstallPack,
  importPack,
  exportPack,
  listTemplates,
  getTemplate,
  applyTemplate,
  seedBuiltins,
  BUILTIN_PACKS,
  BUILTIN_TEMPLATES,
};
