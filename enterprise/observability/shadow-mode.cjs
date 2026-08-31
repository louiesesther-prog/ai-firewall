// ── Shadow Mode (Log-Only AI Usage Detection) ───────────────────────
// Observes prompts/responses and AI service usage to discover shadow AI
// (unsanctioned AI adoption) WITHOUT blocking or modifying anything.
// Every event is recorded with action_taken = 'observed'.

const crypto = require('crypto');

var _db = null;

function init(database) {
  _db = database;
}

// Detects known AI services from a URL or user agent string.
function detectAIService(text) {
  text = String(text || '').toLowerCase();
  var services = [
    { name: 'chatgpt', patterns: ['chatgpt', 'openai', 'chat.openai.com', 'gpt-'] },
    { name: 'claude', patterns: ['claude.ai', 'claude', 'anthropic'] },
    { name: 'gemini', patterns: ['gemini.google', 'bard.google', 'gemini'] },
    { name: 'copilot', patterns: ['github copilot', 'copilot.microsoft', 'bing.com/search', 'copilot'] },
    { name: 'perplexity', patterns: ['perplexity'] },
    { name: 'midjourney', patterns: ['midjourney'] },
    { name: 'notion-ai', patterns: ['notion.so', 'notion ai'] },
    { name: 'jupyter-ai', patterns: ['jupyter'] },
  ];
  for (var i = 0; i < services.length; i++) {
    for (var p = 0; p < services[i].patterns.length; p++) {
      if (text.indexOf(services[i].patterns[p]) !== -1) {
        return services[i].name;
      }
    }
  }
  return 'custom';
}

// Record a shadow observation. Never blocks.
// options: { teamId, userId, source, eventType, aiService, url, prompt, response, piiTypes, riskScore, metadata }
function observe(options) {
  options = options || {};
  if (!_db) return null;

  var aiService = options.aiService || detectAIService((options.url || '') + ' ' + (options.userAgent || ''));
  var piiTypes = options.piiTypes || [];
  var preamble = options.prompt || options.text || '';
  var response = options.response || '';

  var id = _db.run(
    `INSERT INTO shadow_events (team_id, user_id, source, event_type, ai_service, url, prompt_preview, response_preview, pii_detected, pii_types, risk_score, action_taken, metadata)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'observed', ?)`,
    [
      options.teamId || null,
      options.userId || null,
      options.source || 'api',
      options.eventType || 'prompt_sent',
      aiService,
      options.url || null,
      String(preamble).substring(0, 1000),
      String(response).substring(0, 1000),
      piiTypes.length ? 1 : 0,
      JSON.stringify(piiTypes),
      options.riskScore || 0,
      typeof options.metadata === 'string' ? options.metadata : JSON.stringify(options.metadata || {}),
    ]
  );

  return { id: id, aiService: aiService, shadowRecorded: true, actionTaken: 'observed' };
}

// Convenience: observe a browser/navigation event (from extension or agent)
function observeNavigation(options) {
  options = options || {};
  return observe(Object.assign({}, options, { eventType: options.eventType || 'ai_service_seen', source: options.source || 'network' }));
}

// Convenience: observe a prompt send with PII
function observePrompt(options) {
  options = options || {};
  return observe(Object.assign({}, options, { eventType: 'prompt_sent', source: options.source || 'extension' }));
}

// Convenience: observe a response receipt
function observeResponse(options) {
  options = options || {};
  return observe(Object.assign({}, options, { eventType: 'response_received', source: options.source || 'extension' }));
}

// List shadow events (for dashboards / shadow AI discovery)
function listEvents(teamId, options) {
  options = options || {};
  var where = [];
  var params = [];
  if (teamId) { where.push('team_id = ?'); params.push(teamId); }
  if (options.aiService) { where.push('ai_service = ?'); params.push(options.aiService); }
  if (options.eventType) { where.push('event_type = ?'); params.push(options.eventType); }

  var sql = 'SELECT * FROM shadow_events';
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

// Shadow AI discovery: aggregate which AI services are in use per team
function discoverShadowAI(teamId, options) {
  options = options || {};
  var where = [];
  var params = [];
  if (teamId) { where.push('team_id = ?'); params.push(teamId); }

  var sql = `SELECT ai_service, COUNT(*) as events, SUM(pii_detected) as pii_events
             FROM shadow_events`;
  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  sql += ' GROUP BY ai_service ORDER BY events DESC';
  if (options.limit) sql += ' LIMIT ?';

  var stmt = _db.prepare(sql);
  if (where.length) stmt.bind(params);
  if (options.limit) {
    if (where.length) { stmt.bind(params.concat([options.limit])); }
    else { stmt.bind([options.limit]); }
  }
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// Shadow AI by user (who is using unsanctioned AI)
function discoverByUser(teamId, options) {
  options = options || {};
  var where = [];
  var params = [];
  if (teamId) { where.push('team_id = ?'); params.push(teamId); }

  var sql = `SELECT user_id, COUNT(*) as events, COUNT(DISTINCT ai_service) as services, SUM(pii_detected) as pii_events
             FROM shadow_events`;
  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  sql += ' GROUP BY user_id ORDER BY events DESC';
  if (options.limit) sql += ' LIMIT ?';

  var stmt = _db.prepare(sql);
  if (options.limit) {
    var p = where.length ? params.concat([options.limit]) : [options.limit];
    stmt.bind(p);
  } else if (where.length) {
    stmt.bind(params);
  }
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

  var total = 0, pii = 0, services = 0, users = 0;
  var s1 = _db.prepare('SELECT COUNT(*) as c, SUM(pii_detected) as p FROM shadow_events' + w);
  if (where.length) s1.bind(params);
  if (s1.step()) { var r = s1.getAsObject(); total = r.c; pii = r.p || 0; }
  s1.free();

  var s2 = _db.prepare('SELECT COUNT(DISTINCT ai_service) as c FROM shadow_events' + w);
  if (where.length) s2.bind(params);
  if (s2.step()) services = s2.getAsObject().c;
  s2.free();

  var s3 = _db.prepare('SELECT COUNT(DISTINCT user_id) as c FROM shadow_events WHERE user_id IS NOT NULL' + (teamId ? ' AND team_id = ?' : ''));
  if (teamId) s3.bind([teamId]);
  if (s3.step()) users = s3.getAsObject().c;
  s3.free();

  return { totalEvents: total, piiEvents: pii, distinctServices: services, distinctUsers: users };
}

module.exports = {
  init,
  observe,
  observeNavigation,
  observePrompt,
  observeResponse,
  listEvents,
  discoverShadowAI,
  discoverByUser,
  getSummary,
  detectAIService,
};
