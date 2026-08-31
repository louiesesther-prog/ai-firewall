// ── Syslog / CEF Output ──────────────────────────────────────────
// Common Event Format (CEF) output for SIEM integration.

var SEVERITY_MAP = {
  0: 0,   // info
  10: 1,  // low
  30: 3,  // medium
  50: 5,  // high
  70: 7,  // high
  90: 10, // critical
};

function riskToCEFSeverity(riskScore) {
  if (riskScore == null) return 3;
  if (riskScore >= 90) return 10;
  if (riskScore >= 70) return 7;
  if (riskScore >= 50) return 5;
  if (riskScore >= 30) return 3;
  if (riskScore >= 10) return 1;
  return 0;
}

function formatCEF(event) {
  var severity = riskToCEFSeverity(event.riskScore);
  var deviceVersion = '2.1.0';

  var extensions = [
    'msg=' + (event.action || 'PII Detection'),
    'cs1=' + (event.piiTypes ? (Array.isArray(event.piiTypes) ? event.piiTypes.join(',') : event.piiTypes) : 'none'),
    'cs1Label=PII_Types',
    'cs2=' + (event.actionTaken || 'warned'),
    'cs2Label=Action_Taken',
    'cs3=' + (event.source || 'unknown'),
    'cs3Label=Source',
    'cn1=' + (event.riskScore || 0),
    'cn1Label=Risk_Score',
    'cs4=' + (event.service || 'unknown'),
    'cs4Label=AI_Service',
    'dhost=' + (event.hostname || 'unknown'),
    'duser=' + (event.userId || 'unknown'),
    'suser=' + (event.userId || 'unknown'),
    'rt=' + (event.timestamp || new Date().toISOString()),
  ];

  return 'CEF:0|AI-Firewall|ai-firewall|' + deviceVersion + '|' + (event.signature || 'PII-DETECTED') + '|' + (event.name || 'PII Detection') + '|' + severity + '|' + extensions.join(' ');
}

function formatJSON(event) {
  return JSON.stringify({
    timestamp: event.timestamp || new Date().toISOString(),
    severity: riskToCEFSeverity(event.riskScore),
    source: 'ai-firewall',
    version: '2.1.0',
    action: event.action || 'PII Detection',
    piiTypes: event.piiTypes || [],
    actionTaken: event.actionTaken || 'warned',
    riskScore: event.riskScore || 0,
    service: event.service || 'unknown',
    userId: event.userId || 'unknown',
    teamId: event.teamId || null,
    metadata: event.metadata || {},
  });
}

function formatSyslog(event) {
  var severity = riskToCEFSeverity(event.riskScore);
  var facility = 16; // local0
  var priority = facility * 8 + severity;
  var timestamp = event.timestamp || new Date().toISOString();
  var hostname = event.hostname || 'ai-firewall';

  return '<' + priority + '>' + timestamp + ' ' + hostname + ' ai-firewall: ' + formatCEF(event);
}

module.exports = { formatCEF, formatJSON, formatSyslog, riskToCEFSeverity };
