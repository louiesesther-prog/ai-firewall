// ── Alerts (Reactive Notifications) ─────────────────────────────────
// Alert rules react to events (high_risk, pii_detected, policy_violation,
// quota_exceeded, shadow_usage, custom) and deliver to channels:
// webhook, syslog, email (log), log (console), and persist to the alerts
// table. Supports severity thresholds and cooldowns.

const crypto = require('crypto');

var _db = null;
var _webhookDispatcher = null;
var _cooldowns = new Map();

function init(database, webhookDispatcher) {
  _db = database;
  _webhookDispatcher = webhookDispatcher;
}

function _newId() {
  return 'alr_' + Date.now().toString(36) + '_' + crypto.randomBytes(4).toString('hex');
}

// ── Alert Rule CRUD ─────────────────────────────────────────────────

function createRule(options) {
  options = options || {};
  var id = _newId();

  _db.run(
    `INSERT INTO alert_rules (id, team_id, name, description, enabled, event_type, condition, severity, channels, cooldown_seconds, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      id,
      options.teamId || null,
      options.name || 'Alert Rule',
      options.description || null,
      options.enabled !== false ? 1 : 0,
      options.eventType || 'high_risk',
      typeof options.condition === 'string' ? options.condition : JSON.stringify(options.condition || {}),
      options.severity || 'medium',
      typeof options.channels === 'string' ? options.channels : JSON.stringify(options.channels || ['webhook']),
      options.cooldownSeconds || 0,
      options.createdBy || null,
    ]
  );

  return getRule(id);
}

function getRule(id) {
  var stmt = _db.prepare('SELECT * FROM alert_rules WHERE id = ?');
  stmt.bind([id]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  if (!row) return null;
  try { row.condition = JSON.parse(row.condition || '{}'); } catch (e) { row.condition = {}; }
  try { row.channels = JSON.parse(row.channels || '["webhook"]'); } catch (e) { row.channels = ['webhook']; }
  return row;
}

function listRules(teamId, options) {
  options = options || {};
  var where = [];
  var params = [];
  if (teamId) { where.push('team_id = ?'); params.push(teamId); }
  if (!options.includeDisabled) where.push('enabled = 1');

  var sql = 'SELECT * FROM alert_rules';
  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  sql += ' ORDER BY severity DESC, created_at DESC';

  var stmt = _db.prepare(sql);
  if (params.length) stmt.bind(params);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows.map(function(r) {
    try { r.condition = JSON.parse(r.condition || '{}'); } catch (e) { r.condition = {}; }
    try { r.channels = JSON.parse(r.channels || '["webhook"]'); } catch (e) { r.channels = ['webhook']; }
    return r;
  });
}

function updateRule(id, updates) {
  var sets = [];
  var params = [];
  if (updates.name !== undefined) { sets.push('name = ?'); params.push(updates.name); }
  if (updates.description !== undefined) { sets.push('description = ?'); params.push(updates.description); }
  if (updates.enabled !== undefined) { sets.push('enabled = ?'); params.push(updates.enabled ? 1 : 0); }
  if (updates.eventType !== undefined) { sets.push('event_type = ?'); params.push(updates.eventType); }
  if (updates.severity !== undefined) { sets.push('severity = ?'); params.push(updates.severity); }
  if (updates.cooldownSeconds !== undefined) { sets.push('cooldown_seconds = ?'); params.push(updates.cooldownSeconds); }
  if (updates.condition !== undefined) {
    sets.push('condition = ?');
    params.push(typeof updates.condition === 'string' ? updates.condition : JSON.stringify(updates.condition));
  }
  if (updates.channels !== undefined) {
    sets.push('channels = ?');
    params.push(typeof updates.channels === 'string' ? updates.channels : JSON.stringify(updates.channels));
  }
  if (sets.length === 0) return getRule(id);
  sets.push("updated_at = datetime('now')");
  params.push(id);
  _db.run('UPDATE alert_rules SET ' + sets.join(', ') + ' WHERE id = ?', params);
  return getRule(id);
}

function deleteRule(id) {
  _db.run('DELETE FROM alert_rules WHERE id = ?', [id]);
  return { deleted: true };
}

// ── Rule matching & firing ──────────────────────────────────────────

// condition: { minRisk, severityAtLeast, piiTypes[], eventTypes[] }
function _matches(rule, event) {
  var cond = rule.condition || {};
  var e = event || {};

  // Severity threshold
  if (cond.minRisk !== undefined) {
    if ((e.riskScore || 0) < cond.minRisk) return false;
  }
  if (cond.severityAtLeast) {
    if (!severityGE(e.severity || eActionSeverity(e), cond.severityAtLeast)) return false;
  }
  // PII type filter
  if (cond.piiTypes && cond.piiTypes.length) {
    var evTypes = e.piiTypes || [];
    if (!cond.piiTypes.some(pt => evTypes.indexOf(pt) !== -1)) return false;
  }
  // Event type filter (already gated by event_type on rule)
  return true;
}

function eActionSeverity(e) {
  var m = { low: 1, medium: 2, high: 3, critical: 4 };
  return m[(e.severity || '').toLowerCase()] || 0;
}

function severityGE(a, b) {
  var m = { low: 1, medium: 2, high: 3, critical: 4 };
  return (m[String(a).toLowerCase()] || 0) >= (m[String(b).toLowerCase()] || 0);
}

function _inCooldown(ruleId) {
  if (!_cooldowns.has(ruleId)) return false;
  if (Date.now() < _cooldowns.get(ruleId)) return true;
  _cooldowns.delete(ruleId);
  return false;
}

// Evaluate an event across all matching rules for a team and fire alerts.
// event: { eventType, teamId, severity, title, message, payload, riskScore, piiTypes }
function fireEvent(event) {
  if (!_db) return { fired: 0 };

  event = event || {};
  var eventType = event.eventType || event.event_type || 'high_risk';

  var rules = listRules(event.teamId, { includeDisabled: true }).filter(r => r.enabled);
  var fired = { count: 0, alerts: [] };

  for (var i = 0; i < rules.length; i++) {
    var rule = rules[i];
    if (rule.event_type !== eventType && rule.event_type !== 'custom') continue;
    if (!_matches(rule, event)) continue;
    if (_inCooldown(rule.id)) continue;

    // Cooldown
    if (rule.cooldown_seconds > 0) {
      _cooldowns.set(rule.id, Date.now() + rule.cooldown_seconds * 1000);
    }
    _db.run("UPDATE alert_rules SET last_fired_at = datetime('now') WHERE id = ?", [rule.id]);

    var severity = event.severity || rule.severity || 'medium';

    // Persist alert
    var alertId = 'al_' + Date.now().toString(36) + '_' + crypto.randomBytes(4).toString('hex');
    _db.run(
      `INSERT INTO alerts (id, rule_id, team_id, event_type, severity, title, message, payload)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        alertId,
        rule.id,
        event.teamId || null,
        eventType,
        severity,
        event.title || rule.name,
        event.message || (rule.name + ' triggered'),
        typeof event.payload === 'string' ? event.payload : JSON.stringify(event.payload || {}),
      ]
    );

    // Deliver to channels
    var channels = rule.channels || ['webhook'];
    for (var c = 0; c < channels.length; c++) {
      deliver(rule, channels[c], {
        alertId: alertId,
        eventType: eventType,
        severity: severity,
        title: event.title || rule.name,
        message: event.message || (rule.name + ' triggered'),
        payload: event.payload || {},
        riskScore: event.riskScore,
        piiTypes: event.piiTypes,
        teamId: event.teamId,
      });
    }

    fired.count++;
    fired.alerts.push(alertId);
  }

  return fired;
}

// ── Delivery ────────────────────────────────────────────────────────

function deliver(rule, channel, alert) {
  var data = { rule: { id: rule.id, name: rule.name }, alert: alert };
  var payload = JSON.stringify(data);

  switch (channel) {
    case 'webhook':
      if (_webhookDispatcher) {
        try { _webhookDispatcher.dispatchEvent('alert', data); } catch (e) {}
      }
      break;

    case 'syslog':
      try {
        var syslog = require('../integrations/syslog.cjs');
        var line = syslog.formatSyslog({
          riskScore: alert.riskScore,
          piiTypes: alert.piiTypes,
          actionTaken: 'alert',
          source: 'alerts',
          userId: null,
          teamId: alert.teamId,
          name: 'Alert: ' + alert.title,
          action: 'ALERT',
          message: alert.message,
        });
        console.log('[syslog] ' + line);
      } catch (e) {}
      break;

    case 'log':
    case 'console':
      console.log('[alert:' + alert.severity + '] ' + alert.title + ': ' + alert.message);
      break;

    case 'email':
      // No SMTP dependency; log as email-outbound stub
      console.log('[email:outbound] To=<rule:' + rule.name + '> Alert: ' + alert.title);
      break;

    default:
      console.log('[alert] ' + alert.title + ': ' + alert.message);
  }
}

// ── Alert lifecycle ─────────────────────────────────────────────────

function listAlerts(teamId, options) {
  options = options || {};
  var where = [];
  var params = [];
  if (teamId) { where.push('team_id = ?'); params.push(teamId); }
  if (options.status) { where.push('status = ?'); params.push(options.status); }

  var sql = 'SELECT * FROM alerts';
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

function updateAlertStatus(id, status, userId) {
  status = status || 'resolved';
  _db.run(
    "UPDATE alerts SET status = ?, resolved_at = datetime('now'), acknowledged_by = ? WHERE id = ?",
    [status, userId || null, id]
  );
  return { updated: true, status: status };
}

function getAlertStats(teamId) {
  var where = [];
  var params = [];
  if (teamId) { where.push('team_id = ?'); params.push(teamId); }
  var w = where.length ? (' WHERE ' + where.join(' AND ')) : '';

  var stmt = _db.prepare('SELECT status, COUNT(*) as c FROM alerts' + w + ' GROUP BY status');
  if (params.length) stmt.bind(params);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();

  var stats = { total: 0, open: 0, acknowledged: 0, resolved: 0, dismissed: 0 };
  for (var i = 0; i < rows.length; i++) {
    var r = rows[i];
    stats.total += r.c;
    if (r.status === 'open') stats.open = r.c;
    else if (r.status === 'acknowledged') stats.acknowledged = r.c;
    else if (r.status === 'resolved') stats.resolved = r.c;
    else if (r.status === 'dismissed') stats.dismissed = r.c;
  }
  return stats;
}

module.exports = {
  init,
  createRule,
  getRule,
  listRules,
  updateRule,
  deleteRule,
  fireEvent,
  deliver,
  listAlerts,
  updateAlertStatus,
  getAlertStats,
};
