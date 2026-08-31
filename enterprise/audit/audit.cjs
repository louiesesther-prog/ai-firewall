// ── Audit Trail Logger ────────────────────────────────────────────
// Append-only audit event logger. Events are immutable once written.

const crypto = require('crypto');

var _db = null;

function init(database) {
  _db = database;
}

function generateId() {
  return 'aud_' + Date.now().toString(36) + '_' + crypto.randomBytes(8).toString('hex');
}

function logEvent(event) {
  if (!_db) return null;

  var id = generateId();
  var now = new Date().toISOString().replace('T', ' ').substring(0, 19);

  try {
    _db.run(
      `INSERT INTO audit_events (id, timestamp, user_id, team_id, session_id, action, resource_type, resource_id, pii_types, risk_score, action_taken, ip_address, user_agent, metadata, compliance_profile, retention_until)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        now,
        event.userId || null,
        event.teamId || null,
        event.sessionId || null,
        event.action || 'unknown',
        event.resourceType || null,
        event.resourceId || null,
        event.piiTypes ? JSON.stringify(event.piiTypes) : null,
        event.riskScore != null ? event.riskScore : null,
        event.actionTaken || null,
        event.ipAddress || null,
        event.userAgent || null,
        event.metadata ? JSON.stringify(event.metadata) : null,
        event.complianceProfile || null,
        event.retentionUntil || null,
      ]
    );
    return id;
  } catch (e) {
    console.warn('[audit] Write failed:', e.message);
    return null;
  }
}

function logScan(event) {
  return logEvent(Object.assign({ action: 'scan', resourceType: 'text' }, event));
}

function logScrub(event) {
  return logEvent(Object.assign({ action: 'scrub', resourceType: 'text' }, event));
}

function logEncrypt(event) {
  return logEvent(Object.assign({ action: 'encrypt', resourceType: 'text' }, event));
}

function logDecrypt(event) {
  return logEvent(Object.assign({ action: 'decrypt', resourceType: 'text' }, event));
}

function logResponseScan(event) {
  return logEvent(Object.assign({ action: 'response_scan', resourceType: 'ai_response' }, event));
}

function logLogin(event) {
  return logEvent(Object.assign({ action: 'login', resourceType: 'auth' }, event));
}

function logConfigChange(event) {
  return logEvent(Object.assign({ action: 'config_change', resourceType: 'config' }, event));
}

function logPolicyAction(event) {
  return logEvent(Object.assign({ action: 'policy_action', resourceType: 'policy' }, event));
}

function logWebhookDelivery(event) {
  return logEvent(Object.assign({ action: 'webhook_delivery', resourceType: 'webhook' }, event));
}

function logAlert(event) {
  return logEvent(Object.assign({ action: 'alert', resourceType: 'alert' }, event));
}

function logGeneric(event) {
  return logEvent(event);
}

function getEvents(options) {
  if (!_db) return [];
  options = options || {};

  var where = [];
  var params = [];

  if (options.teamId) { where.push('team_id = ?'); params.push(options.teamId); }
  if (options.userId) { where.push('user_id = ?'); params.push(options.userId); }
  if (options.action) { where.push('action = ?'); params.push(options.action); }
  if (options.from) { where.push('timestamp >= ?'); params.push(options.from); }
  if (options.to) { where.push('timestamp <= ?'); params.push(options.to); }

  var sql = 'SELECT * FROM audit_events';
  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  sql += ' ORDER BY timestamp DESC';
  sql += ' LIMIT ?';
  params.push(options.limit || 100);

  try {
    var stmt = _db.prepare(sql);
    if (params.length) stmt.bind(params);
    var rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    return rows;
  } catch (e) {
    console.warn('[audit] Query failed:', e.message);
    return [];
  }
}

function getEventCount(options) {
  if (!_db) return 0;
  options = options || {};

  var where = [];
  var params = [];

  if (options.teamId) { where.push('team_id = ?'); params.push(options.teamId); }
  if (options.userId) { where.push('user_id = ?'); params.push(options.userId); }
  if (options.action) { where.push('action = ?'); params.push(options.action); }
  if (options.from) { where.push('timestamp >= ?'); params.push(options.from); }
  if (options.to) { where.push('timestamp <= ?'); params.push(options.to); }

  var sql = 'SELECT COUNT(*) as count FROM audit_events';
  if (where.length) sql += ' WHERE ' + where.join(' AND ');

  try {
    var stmt = _db.prepare(sql);
    if (params.length) stmt.bind(params);
    var result = null;
    if (stmt.step()) result = stmt.getAsObject();
    stmt.free();
    return result ? result.count : 0;
  } catch (e) {
    return 0;
  }
}

module.exports = {
  init,
  logEvent,
  logScan,
  logScrub,
  logEncrypt,
  logDecrypt,
  logResponseScan,
  logLogin,
  logConfigChange,
  logPolicyAction,
  logWebhookDelivery,
  logAlert,
  logGeneric,
  getEvents,
  getEventCount,
};
