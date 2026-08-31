// ── Advanced Reporting & Analytics ──────────────────────────────────
// Computed-live trend dashboards and aggregate reports across audit,
// policy, alert, usage, shadow, and network tables. No extra storage —
// everything is derived from existing event data so reports stay current.

var _db = null;
var _complianceExport = null;
var _webhookDispatcher = null;

function init(database, complianceExport, webhookDispatcher) {
  _db = database;
  _complianceExport = complianceExport;
  _webhookDispatcher = webhookDispatcher;
}

// Map a period string to a granularity + grouping expression.
// period: '24h' | '7d' | '30d' | '90d'
function _periodStart(period) {
  var now = new Date();
  switch (period) {
    case '24h': return new Date(now.getTime() - 24 * 3600 * 1000);
    case '7d':  return new Date(now.getTime() - 7 * 24 * 3600 * 1000);
    case '90d': return new Date(now.getTime() - 90 * 24 * 3600 * 1000);
    case '30d':
    default:    return new Date(now.getTime() - 30 * 24 * 3600 * 1000);
  }
}

function _iso(period) {
  return _periodStart(period).toISOString().split('T')[0];
}

// ── Trend: detections / events over time ─────────────────────────────
function detectionTrend(teamId, period) {
  period = period || '30d';
  var start = _periodStart(period);
  var startIso = _iso(period);

  // Build scope for audit events
  var where = ["timestamp >= ?"];
  var params = [startIso];
  if (teamId) { where.push('team_id = ?'); params.push(teamId); }

  var stmt = _db.prepare(
    'SELECT substr(timestamp, 1, 10) as day, COUNT(*) as events, ' +
    'SUM(CASE WHEN pii_types IS NOT NULL AND pii_types != "[]" THEN 1 ELSE 0 END) as pii_events, ' +
    'SUM(CASE WHEN risk_score >= 70 THEN 1 ELSE 0 END) as high_risk ' +
    'FROM audit_events WHERE ' + where.join(' AND ') + ' GROUP BY day ORDER BY day ASC'
  );
  stmt.bind(params);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// ── Pie: PII type distribution ───────────────────────────────────────
function piiTypeDistribution(teamId, period) {
  period = period || '30d';
  var startIso = _iso(period);
  var where = ["timestamp >= ?"];
  var params = [startIso];
  if (teamId) { where.push('team_id = ?'); params.push(teamId); }

  var stmt = _db.prepare(
    'SELECT pii_types FROM audit_events WHERE ' + where.join(' AND ') + ' AND pii_types IS NOT NULL AND pii_types != "[]"'
  );
  stmt.bind(params);
  var counts = {};
  while (stmt.step()) {
    var row = stmt.getAsObject();
    try {
      var types = JSON.parse(row.pii_types);
      for (var i = 0; i < types.length; i++) {
        counts[types[i]] = (counts[types[i]] || 0) + 1;
      }
    } catch (e) {}
  }
  stmt.free();
  return Object.keys(counts).map(function(k) { return { piiType: k, count: counts[k] }; })
    .sort(function(a, b) { return b.count - a.count; });
}

// ── Top AI services (from shadow + response scans) ───────────────────
function topAIServices(teamId, period) {
  period = period || '30d';
  var startIso = _iso(period);
  var where = [];
  var params = [];
  if (teamId) { where.push('team_id = ?'); params.push(teamId); }

  var stmt = _db.prepare(
    'SELECT COALESCE(ai_service, "unknown") as service, COUNT(*) as events, ' +
    'SUM(COALESCE(pii_detected,0)) as pii_events, AVG(COALESCE(risk_score,0)) as avg_risk ' +
    'FROM shadow_events' + (where.length ? ' WHERE ' + where.join(' AND ') : '') +
    ' GROUP BY service ORDER BY events DESC LIMIT 10'
  );
  if (where.length) stmt.bind(params);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// ── Top active users (PII risk by user) ──────────────────────────────
function topUsersByRisk(teamId, period) {
  period = period || '30d';
  var startIso = _iso(period);
  var where = ["timestamp >= ?", "user_id IS NOT NULL"];
  var params = [startIso];
  if (teamId) { where.push('team_id = ?'); params.push(teamId); }

  var stmt = _db.prepare(
    'SELECT user_id, COUNT(*) as events, SUM(CASE WHEN risk_score >= 70 THEN 1 ELSE 0 END) as high_risk, ' +
    'AVG(COALESCE(risk_score,0)) as avg_risk ' +
    'FROM audit_events WHERE ' + where.join(' AND ') + ' GROUP BY user_id ORDER BY high_risk DESC, events DESC LIMIT 10'
  );
  stmt.bind(params);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// ── Action breakdown (allow/deny/redact) from policy events ──────────
function policyActionBreakdown(teamId, period) {
  var where = [];
  var params = [];
  if (teamId) { where.push('team_id = ?'); params.push(teamId); }

  var stmt = _db.prepare(
    'SELECT action, COUNT(*) as c FROM policy_events' + (where.length ? ' WHERE ' + where.join(' AND ') : '') + ' GROUP BY action'
  );
  if (where.length) stmt.bind(params);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// ── Alert severity distribution ──────────────────────────────────────
function alertSeverityDistribution(teamId) {
  var where = [];
  var params = [];
  if (teamId) { where.push('team_id = ?'); params.push(teamId); }

  var stmt = _db.prepare(
    'SELECT severity, COUNT(*) as c, SUM(CASE WHEN status="open" THEN 1 ELSE 0 END) as open_c FROM alerts' +
    (where.length ? ' WHERE ' + where.join(' AND ') : '') + ' GROUP BY severity'
  );
  if (where.length) stmt.bind(params);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// ── Usage over time (per API key) ────────────────────────────────────
function usageTrend(teamId, period) {
  var startIso = _iso(period || '30d');
  var where = ['date >= ?'];
  var params = [startIso];
  if (teamId) {
    where.push('ak.team_id = ?'); params.push(teamId);
  }

  var stmt = _db.prepare(
    'SELECT aku.date as day, SUM(aku.requests) as requests, SUM(aku.scrub_operations) as scrubs, SUM(aku.pii_detections) as detections ' +
    'FROM api_key_usage aku INNER JOIN api_keys ak ON aku.key_id = ak.id ' +
    'WHERE ' + where.join(' AND ') + ' GROUP BY aku.date ORDER BY aku.date ASC'
  );
  stmt.bind(params);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// ── Consolidated executive dashboard ─────────────────────────────────
function dashboard(teamId, period) {
  period = period || '30d';
  return {
    period: period,
    detections: detectionTrend(teamId, period),
    piiTypes: piiTypeDistribution(teamId, period),
    topServices: topAIServices(teamId, period),
    topUsers: topUsersByRisk(teamId, period),
    policyActions: policyActionBreakdown(teamId, period),
    alerts: alertSeverityDistribution(teamId),
    usage: usageTrend(teamId, period),
  };
}

// ── Deliverable summary report (markdown) for email/webhook ──────────
function generateSummaryReport(teamId, period) {
  var d = dashboard(teamId, period);
  var lines = [];
  lines.push('# AI Firewall Analytics Report');
  lines.push('');
  lines.push('Period: ' + period);
  lines.push('');

  var totalEvents = d.detections.reduce(function(s, r) { return s + (parseInt(r.events, 10) || 0); }, 0);
  var totalPII = d.detections.reduce(function(s, r) { return s + (parseInt(r.pii_events, 10) || 0); }, 0);
  lines.push('## Overview');
  lines.push('- Total events: ' + totalEvents);
  lines.push('- PII events: ' + totalPII);
  lines.push('');

  lines.push('## Top PII Types');
  d.piiTypes.slice(0, 10).forEach(function(r) { lines.push('- ' + r.piiType + ': ' + r.count); });
  lines.push('');

  lines.push('## Top AI Services');
  d.topServices.slice(0, 5).forEach(function(r) { lines.push('- ' + r.service + ': ' + r.events + ' events (' + (r.pii_events || 0) + ' PII)'); });
  lines.push('');

  lines.push('## Open Alerts');
  d.alerts.forEach(function(r) { lines.push('- ' + r.severity + ': ' + r.c + ' (open ' + r.open_c + ')'); });
  lines.push('');

  return lines.join('\n');
}

// ── Execute a summary report + deliver via webhook ───────────────────
function runReport(teamId, options, webhookEventType) {
  options = options || {};
  var period = options.period || '30d';
  var reportId = 'ar_' + Date.now().toString(36);
  var markdown = generateSummaryReport(teamId, period);

  var report = {
    id: reportId,
    type: options.type || 'analytics_summary',
    teamId: teamId,
    period: period,
    markdown: markdown,
    generatedAt: new Date().toISOString(),
    data: dashboard(teamId, period),
  };

  if (_webhookDispatcher && webhookEventType) {
    try {
      _webhookDispatcher.dispatchEvent(webhookEventType, { report: report });
    } catch (e) {}
  }
  return report;
}

// ── N-day retention health for the tenant ────────────────────────────
function healthCheck(teamId) {
  var result = {
    schemaVersion: 4,
    tables: [],
    lastEventAt: null,
    lastAlertAt: null,
  };
  try {
    var s = _db.prepare('SELECT MAX(timestamp) as t, COUNT(*) as c FROM audit_events' + (teamId ? ' WHERE team_id = ?' : ''));
    if (teamId) s.bind([teamId]);
    if (s.step()) { var r = s.getAsObject(); result.tables.push({ name: 'audit_events', count: r.c, latest: r.t }); result.lastEventAt = r.t; }
    s.free();
  } catch (e) {}
  return result;
}

module.exports = {
  init,
  detectionTrend,
  piiTypeDistribution,
  topAIServices,
  topUsersByRisk,
  policyActionBreakdown,
  alertSeverityDistribution,
  usageTrend,
  dashboard,
  generateSummaryReport,
  runReport,
  healthCheck,
};
