// ── Compliance Export Generator ───────────────────────────────────
// Generates SOC 2, GDPR Art. 30, and HIPAA compliance reports from
// audit trail data.

var _db = null;

function init(database) {
  _db = database;
}

function generateReport(options) {
  if (!_db) return null;
  options = options || {};
  var reportType = options.reportType || 'gdpr_art30';
  var teamId = options.teamId || null;
  var periodStart = options.periodStart || '';
  var periodEnd = options.periodEnd || '';
  var generatedBy = options.generatedBy || 'system';

  var reportId = 'rpt_' + Date.now().toString(36);
  var now = new Date().toISOString().replace('T', ' ').substring(0, 19);

  // Fetch events in period
  var where = ['timestamp >= ?', 'timestamp <= ?'];
  var params = [periodStart, periodEnd];
  if (teamId) { where.unshift('team_id = ?'); params.unshift(teamId); }

  var sql = 'SELECT * FROM audit_events WHERE ' + where.join(' AND ') + ' ORDER BY timestamp ASC';
  var stmt = _db.prepare(sql);
  stmt.bind(params);
  var events = [];
  while (stmt.step()) events.push(stmt.getAsObject());
  stmt.free();

  var report;
  switch (reportType) {
    case 'soc2':
      report = generateSOC2(events, options);
      break;
    case 'gdpr_art30':
      report = generateGDPR30(events, options);
      break;
    case 'hipaa':
      report = generateHIPAA(events, options);
      break;
    default:
      report = generateGeneric(events, options);
  }

  report.id = reportId;
  report.reportType = reportType;
  report.periodStart = periodStart;
  report.periodEnd = periodEnd;
  report.generatedBy = generatedBy;
  report.generatedAt = now;
  report.eventCount = events.length;
  report.teamId = teamId;

  // Store report metadata
  try {
    _db.run(
      `INSERT INTO compliance_reports (id, team_id, report_type, period_start, period_end, generated_by, status, row_count, created_at, completed_at)
       VALUES (?, ?, ?, ?, ?, ?, 'completed', ?, ?, ?)`,
      [reportId, teamId, reportType, periodStart, periodEnd, generatedBy, events.length, now, now]
    );
  } catch (e) {
    console.warn('[compliance] Failed to store report:', e.message);
  }

  return report;
}

function generateSOC2(events, options) {
  var summary = {
    controls: {
      CC6_1: { name: 'Logical Access Controls', description: 'User authentication and access management', status: 'effective' },
      CC6_6: { name: 'System Boundaries', description: 'Network-level PII enforcement', status: events.some(function(e) { return e.action === 'network_block'; }) ? 'effective' : 'not_applicable' },
      CC7_1: { name: 'System Monitoring', description: 'PII detection and audit logging', status: events.length > 0 ? 'effective' : 'not_tested' },
      CC7_2: { name: 'Anomaly Detection', description: 'High-risk PII event detection', status: events.some(function(e) { return e.risk_score && e.risk_score > 70; }) ? 'exceptions_noted' : 'effective' },
      CC8_1: { name: 'Change Management', description: 'Configuration and policy changes', status: events.some(function(e) { return e.action === 'config_change'; }) ? 'effective' : 'not_tested' },
    },
    metrics: {
      totalScans: events.filter(function(e) { return e.action === 'scan' || e.action === 'scrub'; }).length,
      piiDetected: events.filter(function(e) { return e.pii_types && e.pii_types !== '[]'; }).length,
      highRiskEvents: events.filter(function(e) { return e.risk_score && e.risk_score > 70; }).length,
      actionsBlocked: events.filter(function(e) { return e.action_taken === 'blocked'; }).length,
      uniqueUsers: [...new Set(events.filter(function(e) { return e.user_id; }).map(function(e) { return e.user_id; }))].length,
    },
    events: events,
  };
  return summary;
}

function generateGDPR30(events, options) {
  var piiTypes = {};
  events.forEach(function(e) {
    if (e.pii_types) {
      try {
        var types = JSON.parse(e.pii_types);
        types.forEach(function(t) { piiTypes[t] = (piiTypes[t] || 0) + 1; });
      } catch (err) {}
    }
  });

  return {
    controller: options.controller || { name: 'Organization', contact: 'privacy@example.com' },
    processor: options.processor || { name: 'AI Firewall', contact: 'support@ai-firewall.dev' },
    purposes: [
      { description: 'PII detection and masking before AI model interaction', legalBasis: 'Legitimate interest (Art. 6(1)(f))' },
      { description: 'Audit logging for compliance reporting', legalBasis: 'Legal obligation (Art. 6(1)(c))' },
    ],
    dataCategories: Object.keys(piiTypes).map(function(type) {
      return { category: type, count: piiTypes[type] };
    }),
    recipients: options.recipients || [],
    retentionPeriod: options.retentionDays ? options.retentionDays + ' days' : '365 days',
    crossBorderTransfers: options.crossBorderTransfers || [],
    technicalMeasures: [
      'AES-256-GCM encryption for stored PII',
      '100% local processing (no external API calls)',
      'Role-based access control',
      'Audit trail with immutable event logging',
    ],
    events: events,
  };
}

function generateHIPAA(events, options) {
  var phiEvents = events.filter(function(e) {
    return e.pii_types && (
      e.pii_types.includes('SSN') ||
      e.pii_types.includes('DOB') ||
      e.pii_types.includes('EMAIL') ||
      e.pii_types.includes('PHONE') ||
      e.pii_types.includes('ADDRESS')
    );
  });

  return {
    coveredEntity: options.entity || { name: 'Organization', type: 'Covered Entity' },
    businessAssociates: options.businessAssociates || [],
    safeguards: {
      administrative: ['Workforce training', 'Security incident procedures', 'Contingency plan'],
      technical: ['Access control', 'Audit controls', 'Integrity controls', 'Transmission security'],
      physical: ['Facility access controls', 'Workstation security'],
    },
    phiExposures: phiEvents.length,
    totalScans: events.length,
    riskAssessment: {
      likelihood: phiEvents.length > 10 ? 'high' : phiEvents.length > 0 ? 'medium' : 'low',
      impact: events.some(function(e) { return e.risk_score && e.risk_score > 80; }) ? 'high' : 'medium',
    },
    events: events,
  };
}

function generateGeneric(events, options) {
  return {
    summary: {
      totalEvents: events.length,
      uniqueUsers: [...new Set(events.filter(function(e) { return e.user_id; }).map(function(e) { return e.user_id; }))].length,
      actionBreakdown: events.reduce(function(acc, e) { acc[e.action] = (acc[e.action] || 0) + 1; return acc; }, {}),
    },
    events: events,
  };
}

function listReports(options) {
  if (!_db) return [];
  options = options || {};

  var where = [];
  var params = [];

  if (options.teamId) { where.push('team_id = ?'); params.push(options.teamId); }
  if (options.reportType) { where.push('report_type = ?'); params.push(options.reportType); }

  var sql = 'SELECT * FROM compliance_reports';
  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  sql += ' ORDER BY created_at DESC LIMIT ?';
  params.push(options.limit || 50);

  try {
    var stmt = _db.prepare(sql);
    if (params.length) stmt.bind(params);
    var rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    return rows;
  } catch (e) {
    return [];
  }
}

module.exports = { init, generateReport, listReports };
