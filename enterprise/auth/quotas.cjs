// ── Usage Quotas & Rate Limiting ──────────────────────────────────
// Per-team and per-key usage quotas with in-memory rate limiting
// and persistent quota tracking.

var _db = null;
var _rateLimiters = new Map();

function init(database) {
  _db = database;
}

// ── In-memory rate limiter (per API key) ──────────────────────────
function createKeyRateLimiter(keyId, maxRequests, windowMs) {
  var hits = [];
  return function() {
    var now = Date.now();
    hits = hits.filter(function(t) { return now - t < windowMs; });
    if (hits.length >= maxRequests) return false;
    hits.push(now);
    return true;
  };
}

function checkRateLimit(keyId, maxRequests, windowMs) {
  windowMs = windowMs || 60000;
  maxRequests = maxRequests || 60;

  if (!_rateLimiters.has(keyId)) {
    _rateLimiters.set(keyId, createKeyRateLimiter(keyId, maxRequests, windowMs));
  }
  return _rateLimiters.get(keyId)();
}

// ── Quota Management ─────────────────────────────────────────────

function createQuota(teamId, options) {
  options = options || {};
  var id = 'uq_' + Date.now().toString(36) + '_' + require('crypto').randomBytes(4).toString('hex');

  _db.run(
    `INSERT INTO usage_quotas (id, team_id, quota_type, limit_value, period, enabled) VALUES (?, ?, ?, ?, ?, ?)`,
    [id, teamId, options.quotaType || 'monthly_requests', options.limitValue || 100000, options.period || 'monthly', options.enabled !== false ? 1 : 0]
  );

  return { id: id, teamId: teamId, quotaType: options.quotaType || 'monthly_requests', limitValue: options.limitValue || 100000, period: options.period || 'monthly' };
}

function listQuotas(teamId) {
  var stmt = _db.prepare('SELECT * FROM usage_quotas WHERE team_id = ? ORDER BY created_at ASC');
  stmt.bind([teamId]);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function updateQuota(id, updates) {
  var sets = [];
  var params = [];
  if (updates.limitValue !== undefined) { sets.push('limit_value = ?'); params.push(updates.limitValue); }
  if (updates.enabled !== undefined) { sets.push('enabled = ?'); params.push(updates.enabled ? 1 : 0); }
  if (updates.quotaType !== undefined) { sets.push('quota_type = ?'); params.push(updates.quotaType); }
  if (updates.period !== undefined) { sets.push('period = ?'); params.push(updates.period); }
  if (sets.length === 0) return null;
  params.push(id);
  _db.run('UPDATE usage_quotas SET ' + sets.join(', ') + ' WHERE id = ?', params);
  return { updated: true };
}

function deleteQuota(id) {
  _db.run('DELETE FROM usage_quotas WHERE id = ?', [id]);
  return { deleted: true };
}

function checkQuota(teamId, quotaType) {
  var stmt = _db.prepare('SELECT * FROM usage_quotas WHERE team_id = ? AND quota_type = ? AND enabled = 1');
  stmt.bind([teamId, quotaType]);
  var quota = null;
  if (stmt.step()) quota = stmt.getAsObject();
  stmt.free();

  if (!quota) return { allowed: true, reason: 'no_quota_set' };

  // Get current usage for the period
  var usage = getTeamUsage(teamId, quota.period);
  if (usage.total >= quota.limit_value) {
    return {
      allowed: false,
      reason: 'quota_exceeded',
      quotaType: quotaType,
      limit: quota.limit_value,
      used: usage.total,
      period: quota.period,
    };
  }

  return {
    allowed: true,
    remaining: quota.limit_value - usage.total,
    limit: quota.limit_value,
    used: usage.total,
    period: quota.period,
  };
}

function getTeamUsage(teamId, period) {
  period = period || 'monthly';
  var now = new Date();
  var startDate;

  if (period === 'daily') {
    startDate = now.toISOString().split('T')[0];
  } else if (period === 'monthly') {
    startDate = now.toISOString().substring(0, 7) + '-01';
  } else if (period === 'yearly') {
    startDate = now.toISOString().substring(0, 4) + '-01-01';
  } else {
    startDate = '2000-01-01';
  }

  // Sum usage across all API keys for this team
  var stmt = _db.prepare(`
    SELECT COALESCE(SUM(aku.requests), 0) as total,
           COALESCE(SUM(aku.pii_detections), 0) as detections,
           COALESCE(SUM(aku.scrub_operations), 0) as scrubs,
           COALESCE(SUM(aku.scan_operations), 0) as scans,
           COALESCE(SUM(aku.response_scans), 0) as response_scans
    FROM api_key_usage aku
    INNER JOIN api_keys ak ON aku.key_id = ak.id
    WHERE ak.team_id = ? AND aku.date >= ?
  `);
  stmt.bind([teamId, startDate]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  return row || { total: 0, detections: 0, scrubs: 0, scans: 0, response_scans: 0 };
}

// ── Quota Middleware (for Express) ────────────────────────────────
function quotaMiddleware(teamIdHeader, quotaType) {
  teamIdHeader = teamIdHeader || 'x-team-id';
  quotaType = quotaType || 'monthly_requests';

  return function(req, res, next) {
    var teamId = req.headers[teamIdHeader.toLowerCase()];
    if (!teamId) return next();

    var result = checkQuota(teamId, quotaType);
    res.setHeader('X-Quota-Limit', result.limit || 'unlimited');
    res.setHeader('X-Quota-Remaining', result.remaining !== undefined ? result.remaining : 'unlimited');

    if (!result.allowed) {
      return res.status(429).json({
        error: 'Quota exceeded',
        reason: result.reason,
        limit: result.limit,
        used: result.used,
        period: result.period,
      });
    }
    next();
  };
}

module.exports = {
  init,
  checkRateLimit,
  createQuota,
  listQuotas,
  updateQuota,
  deleteQuota,
  checkQuota,
  getTeamUsage,
  quotaMiddleware,
};
