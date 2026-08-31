// ── Policy Engine (Data Guardrails) ─────────────────────────────────
// Evaluates inbound/outbound content against policy rules and performs
// the configured action: allow | deny | redact | quarantine.
//
// A policy matches when its conditions are satisfied. Conditions are a
// JSON object:
//   {
//     "piiTypes": ["email", "ssn"],        // must contain any of these
//     "minRisk": 70,                        // risk score must be >=
//     "detectionCount": 3,                  // at least N detections
//     "matchedAny": true,                   // "any" vs "all" of above
//     "keywords": ["confidential", "secret"],
//     "maxLength": 10000,                   // content length limit
//     "channels": ["outbound", "prompt"],   // target channels
//   }
//
// Returns a normalized decision object consumed by callers (API, agent,
// shadow hooks).

const crypto = require('crypto');

var _db = null;

function init(database) {
  _db = database;
}

function _newId() {
  return 'pol_' + Date.now().toString(36) + '_' + crypto.randomBytes(4).toString('hex');
}

// ── Rule CRUD ───────────────────────────────────────────────────────

function createPolicy(options) {
  options = options || {};
  var id = _newId();

  _db.run(
    `INSERT INTO policies (id, team_id, name, description, enabled, priority, action, scope, conditions, channel, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      id,
      options.teamId || null,
      options.name || 'Untitled Policy',
      options.description || null,
      options.enabled !== false ? 1 : 0,
      options.priority || 500,
      options.action || 'allow',
      options.scope || '*',
      typeof options.conditions === 'string' ? options.conditions : JSON.stringify(options.conditions || {}),
      options.channel || 'all',
      options.createdBy || null,
    ]
  );

  return getPolicy(id);
}

function getPolicy(id) {
  var stmt = _db.prepare('SELECT * FROM policies WHERE id = ?');
  stmt.bind([id]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  if (!row) return null;
  try { row.conditions = JSON.parse(row.conditions || '{}'); } catch (e) { row.conditions = {}; }
  return row;
}

function listPolicies(teamId, options) {
  options = options || {};
  var where = [];
  var params = [];
  if (teamId) { where.push('team_id = ?'); params.push(teamId); }
  if (!options.includeDisabled) where.push('enabled = 1');

  var sql = 'SELECT * FROM policies';
  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  sql += ' ORDER BY priority DESC, created_at ASC';

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

function updatePolicy(id, updates) {
  var sets = [];
  var params = [];
  if (updates.name !== undefined) { sets.push('name = ?'); params.push(updates.name); }
  if (updates.description !== undefined) { sets.push('description = ?'); params.push(updates.description); }
  if (updates.enabled !== undefined) { sets.push('enabled = ?'); params.push(updates.enabled ? 1 : 0); }
  if (updates.priority !== undefined) { sets.push('priority = ?'); params.push(updates.priority); }
  if (updates.action !== undefined) { sets.push('action = ?'); params.push(updates.action); }
  if (updates.scope !== undefined) { sets.push('scope = ?'); params.push(updates.scope); }
  if (updates.channel !== undefined) { sets.push('channel = ?'); params.push(updates.channel); }
  if (updates.conditions !== undefined) {
    sets.push('conditions = ?');
    params.push(typeof updates.conditions === 'string' ? updates.conditions : JSON.stringify(updates.conditions));
  }
  if (sets.length === 0) return getPolicy(id);
  sets.push("updated_at = datetime('now')");
  params.push(id);
  _db.run('UPDATE policies SET ' + sets.join(', ') + ' WHERE id = ?', params);
  return getPolicy(id);
}

function deletePolicy(id) {
  _db.run('DELETE FROM policies WHERE id = ?', [id]);
  return { deleted: true };
}

// ── Condition evaluation ────────────────────────────────────────────

function _containsPii(piiTypes, detectedTypes) {
  if (!piiTypes || !piiTypes.length) return false;
  var d = (detectedTypes || []).map(function(t) { return String(t).toLowerCase(); });
  return piiTypes.some(function(t) {
    var need = String(t).toLowerCase();
    if (need === '*' ) return true;
    return d.indexOf(need) !== -1;
  });
}

function _evaluateConditions(conditions, context) {
  conditions = conditions || {};
  context = context || {};
  var results = {
    piiTypes: _containsPii(conditions.piiTypes, context.piiTypes),
    minRisk: (conditions.minRisk || 0) <= (context.riskScore || 0),
    detectionCount: (context.piiCount || 0) >= (conditions.detectionCount || 1),
    keywords: true,
    maxLength: (context.contentLength || 0) <= (conditions.maxLength || Infinity),
  };

  // Keywords check
  if (conditions.keywords && conditions.keywords.length) {
    var text = (context.text || '').toLowerCase();
    results.keywords = conditions.keywords.some(function(k) {
      return text.indexOf(String(k).toLowerCase()) !== -1;
    });
  }

  // "Channels" filter is handled by caller (scene/scope gating); not part of match result.

  var keys = ['piiTypes', 'minRisk', 'detectionCount'];
  if (conditions.keywords) keys.push('keywords');
  if (conditions.maxLength) keys.push('maxLength');

  var matched = conditions.matchedAny ? keys.some(k => results[k]) : keys.every(k => results[k]);
  return { matched: matched, results: results };
}

// ── Enforcement ─────────────────────────────────────────────────────

// Scans content against enabled policies for a channel/scope, returns
// the decision of the highest-priority matching policy.
// context: { teamId, userId, scope, channel, piiTypes, piiCount, riskScore, text, contentLength, source }
function evaluate(context) {
  context = context || {};
  context.channel = context.channel || 'all';
  context.scope = context.scope || '*';
  context.piiTypes = context.piiTypes || [];
  context.piiCount = context.piiCount !== undefined ? context.piiCount : (context.piiTypes ? context.piiTypes.length : 0);
  context.riskScore = context.riskScore || 0;
  if (context.text !== undefined && context.contentLength === undefined) {
    context.contentLength = context.text.length;
  }

  var policies = [];
  if (_db) {
    policies = listPolicies(context.teamId, { includeDisabled: true });
  }

  // Sort by priority desc
  policies.sort(function(a, b) { return (b.priority || 0) - (a.priority || 0); });

  var applied = null;
  for (var i = 0; i < policies.length; i++) {
    var p = policies[i];
    if (!p.enabled) continue;
    // Scope gating: policy scope must be '*' or match context scope/channel
    if (p.scope && p.scope !== '*' && p.scope !== context.scope && !isScopeMatch(p.scope, context)) continue;
    if (p.channel && p.channel !== 'all' && p.channel !== context.channel) continue;

    var cond = _evaluateConditions(p.conditions || {}, context);
    if (cond.matched) {
      applied = p;
      break;
    }
  }

  if (!applied) {
    return { allowed: true, action: 'allow', matched: false, policy: null };
  }

  var action = applied.action || 'allow';
  recordEvent(applied, context, action);

  return {
    allowed: action === 'allow',
    action: action,
    matched: true,
    policy: { id: applied.id, name: applied.name, priority: applied.priority, action: action },
    message: policyMessage(action, applied.name),
  };
}

function isScopeMatch(scope, context) {
  // Support comma or space separated scopes e.g. "scrub,scan" and wildcard segments
  var scopes = String(scope).split(/[\s,]+/).filter(Boolean);
  return scopes.indexOf(context.scope) !== -1 || scopes.indexOf(context.channel) !== -1;
}

function policyMessage(action, name) {
  switch (action) {
    case 'deny': return 'Blocked by policy "' + name + '"';
    case 'redact': return 'PII redacted by policy "' + name + '"';
    case 'quarantine': return 'Content quarantined by policy "' + name + '"';
    default: return 'Allowed (policy "' + name + '")';
  }
}

function recordEvent(policy, context, action) {
  if (!_db) return;
  try {
    _db.run(
      `INSERT INTO policy_events (policy_id, team_id, user_id, action, scope, pii_types, risk_score, metadata)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        policy.id,
        context.teamId || null,
        context.userId || null,
        action,
        context.scope,
        JSON.stringify(context.piiTypes || []),
        context.riskScore || 0,
        JSON.stringify({ source: context.source || null, channel: context.channel || null }),
      ]
    );
  } catch (e) { /* non-blocking */ }
}

// ── Convenience helpers ─────────────────────────────────────────────

// Highest-priority deny/redact policy that a team has (for dashboards)
function getEffectivePolicy(teamId, scope) {
  var list = listPolicies(teamId, { includeDisabled: true })
    .filter(p => p.enabled)
    .sort((a, b) => (b.priority || 0) - (a.priority || 0));
  return list[0] || null;
}

function getPolicyEvents(teamId, options) {
  options = options || {};
  var where = [];
  var params = [];
  if (teamId) { where.push('team_id = ?'); params.push(teamId); }
  var sql = 'SELECT * FROM policy_events';
  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  sql += ' ORDER BY created_at DESC LIMIT ?';
  params.push(options.limit || 50);
  var stmt = _db.prepare(sql);
  stmt.bind(params);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

module.exports = {
  init,
  createPolicy,
  getPolicy,
  listPolicies,
  updatePolicy,
  deletePolicy,
  evaluate,
  getPolicyEvents,
  getEffectivePolicy,
};
