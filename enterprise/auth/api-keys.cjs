// ── API Key Management ────────────────────────────────────────────
// Generate, list, revoke, rotate API keys with per-key rate limits
// and usage tracking.

const crypto = require('crypto');

var _db = null;

function init(database) {
  _db = database;
}

function generateKey(teamId, options) {
  options = options || {};
  var rawKey = 'afw_' + crypto.randomBytes(32).toString('hex');
  var keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
  var keyPrefix = rawKey.substring(0, 12);
  var id = 'ak_' + Date.now().toString(36) + '_' + crypto.randomBytes(4).toString('hex');

  var scopes = options.scopes || '["scrub","scan"]';
  if (typeof scopes !== 'string') scopes = JSON.stringify(scopes);

  _db.run(
    `INSERT INTO api_keys (id, team_id, name, key_hash, key_prefix, scopes, rate_limit, quota_daily, created_by, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      id,
      teamId,
      options.name || 'API Key',
      keyHash,
      keyPrefix,
      scopes,
      options.rateLimit || 60,
      options.quotaDaily || 10000,
      options.createdBy || null,
      options.expiresAt || null,
    ]
  );

  return {
    id: id,
    key: rawKey,
    keyPrefix: keyPrefix,
    name: options.name || 'API Key',
    teamId: teamId,
    scopes: scopes,
    rateLimit: options.rateLimit || 60,
    quotaDaily: options.quotaDaily || 10000,
    expiresAt: options.expiresAt || null,
  };
}

function listKeys(teamId, options) {
  options = options || {};
  var where = ['team_id = ?'];
  var params = [teamId];

  if (!options.includeRevoked) {
    where.push('revoked_at IS NULL');
  }

  var sql = 'SELECT id, team_id, name, key_prefix, scopes, rate_limit, quota_daily, enabled, last_used_at, expires_at, created_at, revoked_at FROM api_keys WHERE ' + where.join(' AND ') + ' ORDER BY created_at DESC';
  if (options.limit) {
    sql += ' LIMIT ?';
    params.push(options.limit);
  }

  var stmt = _db.prepare(sql);
  stmt.bind(params);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function getKey(id) {
  var stmt = _db.prepare('SELECT id, team_id, name, key_prefix, scopes, rate_limit, quota_daily, enabled, last_used_at, expires_at, created_at, revoked_at FROM api_keys WHERE id = ?');
  stmt.bind([id]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  return row;
}

function validateKey(rawKey) {
  if (!rawKey || !rawKey.startsWith('afw_')) return null;

  var keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');

  var stmt = _db.prepare(
    'SELECT id, team_id, name, scopes, rate_limit, quota_daily, enabled, expires_at FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL'
  );
  stmt.bind([keyHash]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();

  if (!row) return null;
  if (!row.enabled) return null;
  if (row.expires_at && new Date(row.expires_at) < new Date()) return null;

  // Update last_used_at
  try {
    _db.run("UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?", [row.id]);
  } catch (e) { /* non-blocking */ }

  return row;
}

function revokeKey(id) {
  _db.run("UPDATE api_keys SET revoked_at = datetime('now'), enabled = 0 WHERE id = ?", [id]);
  return { revoked: true };
}

function rotateKey(id, teamId) {
  var existing = getKey(id);
  if (!existing || existing.team_id !== teamId) return null;

  // Revoke old key
  revokeKey(id);

  // Generate new key with same settings
  return generateKey(teamId, {
    name: existing.name + ' (rotated)',
    scopes: existing.scopes,
    rateLimit: existing.rate_limit,
    quotaDaily: existing.quota_daily,
    createdBy: existing.created_by,
  });
}

function updateKey(id, updates) {
  var sets = [];
  var params = [];

  if (updates.name !== undefined) { sets.push('name = ?'); params.push(updates.name); }
  if (updates.scopes !== undefined) {
    sets.push('scopes = ?');
    params.push(typeof updates.scopes === 'string' ? updates.scopes : JSON.stringify(updates.scopes));
  }
  if (updates.rateLimit !== undefined) { sets.push('rate_limit = ?'); params.push(updates.rateLimit); }
  if (updates.quotaDaily !== undefined) { sets.push('quota_daily = ?'); params.push(updates.quotaDaily); }
  if (updates.enabled !== undefined) { sets.push('enabled = ?'); params.push(updates.enabled ? 1 : 0); }
  if (updates.expiresAt !== undefined) { sets.push('expires_at = ?'); params.push(updates.expiresAt); }

  if (sets.length === 0) return getKey(id);

  params.push(id);
  _db.run('UPDATE api_keys SET ' + sets.join(', ') + ' WHERE id = ?', params);
  return getKey(id);
}

function recordUsage(keyId, operationType) {
  var today = new Date().toISOString().split('T')[0];

  try {
    _db.run(
      `INSERT INTO api_key_usage (key_id, date, requests, pii_detections, scrub_operations, scan_operations, response_scans)
       VALUES (?, ?, 1, 0, 0, 0, 0)
       ON CONFLICT(key_id, date) DO UPDATE SET requests = requests + 1`,
      [keyId, today]
    );

    if (operationType === 'scrub') {
      _db.run('UPDATE api_key_usage SET scrub_operations = scrub_operations + 1 WHERE key_id = ? AND date = ?', [keyId, today]);
    } else if (operationType === 'scan') {
      _db.run('UPDATE api_key_usage SET scan_operations = scan_operations + 1 WHERE key_id = ? AND date = ?', [keyId, today]);
    } else if (operationType === 'response_scan') {
      _db.run('UPDATE api_key_usage SET response_scans = response_scans + 1 WHERE key_id = ? AND date = ?', [keyId, today]);
    }
  } catch (e) { /* non-blocking */ }
}

function recordDetection(keyId, count) {
  var today = new Date().toISOString().split('T')[0];
  try {
    _db.run(
      'UPDATE api_key_usage SET pii_detections = pii_detections + ? WHERE key_id = ? AND date = ?',
      [count, keyId, today]
    );
  } catch (e) { /* non-blocking */ }
}

function getUsage(keyId, options) {
  options = options || {};
  var where = ['key_id = ?'];
  var params = [keyId];

  if (options.from) { where.push('date >= ?'); params.push(options.from); }
  if (options.to) { where.push('date <= ?'); params.push(options.to); }

  var sql = 'SELECT * FROM api_key_usage WHERE ' + where.join(' AND ') + ' ORDER BY date DESC';
  if (options.limit) { sql += ' LIMIT ?'; params.push(options.limit); }

  var stmt = _db.prepare(sql);
  stmt.bind(params);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function getUsageToday(keyId) {
  var today = new Date().toISOString().split('T')[0];
  var stmt = _db.prepare('SELECT * FROM api_key_usage WHERE key_id = ? AND date = ?');
  stmt.bind([keyId, today]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  return row || { key_id: keyId, date: today, requests: 0, pii_detections: 0, scrub_operations: 0, scan_operations: 0, response_scans: 0 };
}

function checkQuota(keyId) {
  var key = getKey(keyId);
  if (!key) return { allowed: false, reason: 'key_not_found' };

  var usage = getUsageToday(keyId);
  if (key.quota_daily && usage.requests >= key.quota_daily) {
    return { allowed: false, reason: 'daily_quota_exceeded', limit: key.quota_daily, used: usage.requests };
  }

  return { allowed: true, remaining: (key.quota_daily || 10000) - usage.requests };
}

module.exports = {
  init,
  generateKey,
  listKeys,
  getKey,
  validateKey,
  revokeKey,
  rotateKey,
  updateKey,
  recordUsage,
  recordDetection,
  getUsage,
  getUsageToday,
  checkQuota,
};
