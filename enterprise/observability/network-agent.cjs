// ── Network Agent (Connection-Level PII Detection) ──────────────────
// Detects traffic / connections to AI services and any PII that may be
// in a payload snapshot. Emits network_events. Default action is
// 'observed' (does not block traffic); can be configured to 'flag' when
// attached to a proxy/agent that inspects payloads.

var _db = null;
var _status = 'standby'; // standby | monitoring | active

function init(database) {
  _db = database;
}

function setStatus(s) {
  _status = s;
  return _status;
}

function getStatus() {
  return _status;
}

// Normalize/parse a connection observation.
// options: { teamId, sourceIp, destIp, destPort, protocol, domain, domainName, aiService, connectionType, payload, piiTypes, riskScore, actionTaken, metadata }
function recordConnection(options) {
  options = options || {};
  if (!_db) return null;

  var domain = options.domain || options.domainName || null;
  var aiService = options.aiService || null;
  if (!aiService && domain) {
    aiService = detectAIService(domain);
  }

  var payloadPreview = options.payload ? String(options.payload).substring(0, 500) : null;
  var piiTypes = options.piiTypes || [];

  var id = _db.run(
    `INSERT INTO network_events (team_id, source_ip, dest_ip, dest_port, protocol, domain, ai_service, connection_type, payload_preview, pii_detected, pii_types, risk_score, action_taken, metadata)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      options.teamId || null,
      options.sourceIp || options.srcIp || null,
      options.destIp || options.dstIp || null,
      options.destPort || options.dstPort || null,
      options.protocol || 'tcp',
      domain,
      aiService,
      options.connectionType || 'outbound',
      payloadPreview,
      piiTypes.length ? 1 : 0,
      JSON.stringify(piiTypes),
      options.riskScore || 0,
      options.actionTaken || 'observed',
      typeof options.metadata === 'string' ? options.metadata : JSON.stringify(options.metadata || {}),
    ]
  );

  return { id: id, aiService: aiService, recorded: true, actionTaken: options.actionTaken || 'observed' };
}

// Helper: analyze a payload buffer/string for PII indicators.
// Returns detected PII types (lightweight heuristic, not full scanner).
function analyzePayload(payload) {
  if (!payload) return { piiTypes: [], riskScore: 0 };
  var text = String(payload);
  var types = [];

  if (/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(text)) types.push('email');
  if (/\b\d{3}-\d{2}-\d{4}\b/.test(text)) types.push('ssn');
  if (/\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/.test(text)) types.push('phone');
  if (/\b\d{13,19}\b/.test(text.replace(/[\s-]/g, ''))) types.push('credit_card');
  if (/\b(?:[0-9A-F]{4}[- ]?){5}[0-9A-F]\b/i.test(text)) types.push('mac');
  if (/\bSECRET\b|\bPASSWORD\b|\bAPI[_-]?KEY\b|\bTOKEN\b/i.test(text)) types.push('credential');

  var risk = types.length > 0 ? Math.min(100, types.length * 40) : 0;
  return { piiTypes: types, riskScore: risk };
}

function detectAIService(host) {
  host = String(host || '').toLowerCase();
  var map = {
    'chatgpt.com': 'chatgpt',
    'chat.openai.com': 'chatgpt',
    'openai.com': 'chatgpt',
    'anthropic.com': 'claude',
    'claude.ai': 'claude',
    'gemini.google.com': 'gemini',
    'aistudio.google.com': 'gemini',
    'githubcopilot.com': 'copilot',
    'copilot.microsoft.com': 'copilot',
    'perplexity.ai': 'perplexity',
  };
  if (map[host]) return map[host];
  for (var k in map) {
    if (host.indexOf(k) !== -1) return map[k];
  }
  return null;
}

// List network events
function listEvents(teamId, options) {
  options = options || {};
  var where = [];
  var params = [];
  if (teamId) { where.push('team_id = ?'); params.push(teamId); }
  if (options.aiService) { where.push('ai_service = ?'); params.push(options.aiService); }
  if (options.sourceIp) { where.push('source_ip = ?'); params.push(options.sourceIp); }

  var sql = 'SELECT * FROM network_events';
  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  sql += ' ORDER BY created_at DESC LIMIT ?';
  params.push(options.limit || 100);

  var stmt = _db.prepare(sql);
  stmt.bind(params);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function getSummary(teamId) {
  var where = [];
  var params = [];
  if (teamId) { where.push('team_id = ?'); params.push(teamId); }
  var w = where.length ? (' WHERE ' + where.join(' AND ')) : '';

  var total = 0, ai = 0, pii = 0, services = 0;
  var s1 = _db.prepare('SELECT COUNT(*) as c, SUM(pii_detected) as p FROM network_events' + w);
  if (where.length) s1.bind(params);
  if (s1.step()) { var r = s1.getAsObject(); total = r.c; pii = r.p || 0; }
  s1.free();

  var s2 = _db.prepare('SELECT COUNT(*) as c FROM network_events WHERE ai_service IS NOT NULL' + (teamId ? ' AND team_id = ?' : ''));
  if (teamId) s2.bind([teamId]);
  if (s2.step()) ai = s2.getAsObject().c;
  s2.free();

  var s3 = _db.prepare('SELECT COUNT(DISTINCT ai_service) as c FROM network_events WHERE ai_service IS NOT NULL' + (teamId ? ' AND team_id = ?' : ''));
  if (teamId) s3.bind([teamId]);
  if (s3.step()) services = s3.getAsObject().c;
  s3.free();

  return { totalConnections: total, aiServiceConnections: ai, piiPayloads: pii, distinctServices: services, status: _status };
}

module.exports = {
  init,
  recordConnection,
  analyzePayload,
  detectAIService,
  listEvents,
  getSummary,
  setStatus,
  getStatus,
};
