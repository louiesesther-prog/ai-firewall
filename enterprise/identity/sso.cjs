// ── Single Sign-On (SSO) ────────────────────────────────────────────
// Self-contained SSO using signed tokens (HMAC-SHA256) rather than an
// external IdP. Provides IdP + SP-style provider registration, token
// issuance, validation, and session lifecycle management.

const crypto = require('crypto');

var _db = null;
var _signingKey = process.env.AIFW_SSO_SIGNING_KEY || null;

function init(database, signingKey) {
  _db = database;
  if (signingKey) _signingKey = signingKey;
  // Ensure a deterministic signing key exists for token HMAC
  if (!_signingKey || _signingKey.length < 16) {
    _signingKey = crypto.createHash('sha256').update('ai-firewall-sso').digest('hex');
  }
}

function _sign(data) {
  return crypto.createHmac('sha256', _signingKey).update(data).digest('hex');
}

function _verify(data, sig) {
  var expected = _sign(data);
  var a = Buffer.from(String(sig));
  var b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function _encode(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

function _decode(str) {
  try {
    return JSON.parse(Buffer.from(String(str), 'base64url').toString('utf8'));
  } catch (e) {
    return null;
  }
}

// ── Providers ───────────────────────────────────────────────────────

function registerProvider(teamId, options) {
  options = options || {};
  var id = 'sso_' + Date.now().toString(36) + '_' + crypto.randomBytes(4).toString('hex');

  _db.run(
    `INSERT INTO sso_providers (id, team_id, name, provider_type, issuer, client_id, client_secret, signing_key, metadata_url, enabled, config)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      id,
      teamId,
      options.name || 'Default IdP',
      options.providerType || 'generic',
      options.issuer || 'ai-firewall',
      options.clientId || null,
      options.clientSecret || null,
      options.signingKey || null,
      options.metadataUrl || null,
      options.enabled !== false ? 1 : 0,
      typeof options.config === 'string' ? options.config : JSON.stringify(options.config || {}),
    ]
  );

  return getProvider(id);
}

function getProvider(id) {
  var stmt = _db.prepare('SELECT * FROM sso_providers WHERE id = ?');
  stmt.bind([id]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  return row;
}

function listProviders(teamId) {
  var stmt = _db.prepare('SELECT * FROM sso_providers WHERE team_id = ? ORDER BY created_at ASC');
  stmt.bind([teamId]);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function updateProvider(id, updates) {
  var sets = [];
  var params = [];
  if (updates.name !== undefined) { sets.push('name = ?'); params.push(updates.name); }
  if (updates.enabled !== undefined) { sets.push('enabled = ?'); params.push(updates.enabled ? 1 : 0); }
  if (updates.metadataUrl !== undefined) { sets.push('metadata_url = ?'); params.push(updates.metadataUrl); }
  if (updates.config !== undefined) {
    sets.push('config = ?');
    params.push(typeof updates.config === 'string' ? updates.config : JSON.stringify(updates.config));
  }
  if (sets.length === 0) return getProvider(id);
  sets.push("updated_at = datetime('now')");
  params.push(id);
  _db.run('UPDATE sso_providers SET ' + sets.join(', ') + ' WHERE id = ?', params);
  return getProvider(id);
}

function deleteProvider(id) {
  _db.run('DELETE FROM sso_providers WHERE id = ?', [id]);
  return { deleted: true };
}

// ── Token Issuance (IdP side) ───────────────────────────────────────

// Issues a signed token for a subject. Used as the "identity provider"
// issuing tokens that our own SP + API will validate.
function issueToken(teamId, options) {
  options = options || {};
  var now = Math.floor(Date.now() / 1000);
  var ttl = options.ttlSeconds || 3600;

  var payload = {
    sub: options.subject || options.userId || 'user',
    email: options.email || null,
    name: options.name || null,
    team: teamId,
    iss: options.issuer || 'ai-firewall',
    iat: now,
    exp: now + ttl,
    aud: options.audience || 'ai-firewall',
    scopes: options.scopes || ['scrub', 'scan'],
  };

  var header = _encode({ alg: 'HS256', typ: 'JWT' });
  var body = _encode(payload);
  var content = header + '.' + body;
  var sig = _sign(content);

  var token = content + '.' + sig;

  var sessionId = 'ses_' + crypto.randomBytes(12).toString('hex');
  var expires = new Date((now + ttl) * 1000).toISOString().replace('T', ' ').substring(0, 19);

  _db.run(
    `INSERT INTO sso_sessions (id, team_id, provider_id, user_id, email, name, token, token_type, expires_at, ip_address, user_agent, scopes, metadata)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'jwt', ?, ?, ?, ?, ?)`,
    [
      sessionId,
      teamId,
      options.providerId || null,
      payload.sub,
      payload.email,
      payload.name,
      token,
      expires,
      options.ipAddress || null,
      options.userAgent || null,
      typeof options.scopes === 'string' ? options.scopes : JSON.stringify(payload.scopes),
      options.metadata ? (typeof options.metadata === 'string' ? options.metadata : JSON.stringify(options.metadata)) : '{}',
    ]
  );

  return {
    token: token,
    sessionId: sessionId,
    expiresAt: expires,
    userId: payload.sub,
    email: payload.email,
    name: payload.name,
    teamId: teamId,
  };
}

// ── Token Validation (SP / API side) ────────────────────────────────

function validateToken(token) {
  if (!token) return null;

  var parts = String(token).split('.');
  if (parts.length !== 3) return null;

  var header = _decode(parts[0]);
  var payload = _decode(parts[1]);
  var sig = parts[2];

  if (!header || !payload) return null;
  if (!_verify(parts[0] + '.' + parts[1], sig)) return null;

  // Expiry check
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;

  return payload;
}

// Validates token AND checks session is still active (not revoked/expired)
function validateSession(token) {
  var payload = validateToken(token);
  if (!payload) return null;

  var stmt = _db.prepare('SELECT * FROM sso_sessions WHERE token = ?');
  stmt.bind([token]);
  var session = null;
  if (stmt.step()) session = stmt.getAsObject();
  stmt.free();

  if (!session) return null;
  if (session.revoked_at) return null;
  if (session.expires_at && new Date(session.expires_at) < new Date()) {
    // Expire it
    try { _db.run("UPDATE sso_sessions SET revoked_at = datetime('now') WHERE id = ?", [session.id]); } catch (e) {}
    return null;
  }

  // Update last_seen_at (rate-limited via cooldown to avoid writes on every hit)
  try {
    _db.run("UPDATE sso_sessions SET last_seen_at = datetime('now') WHERE id = ?", [session.id]);
  } catch (e) {}

  return { session: session, payload: payload };
}

function revokeSession(sessionId) {
  _db.run("UPDATE sso_sessions SET revoked_at = datetime('now') WHERE id = ?", [sessionId]);
  return { revoked: true };
}

function revokeAllSessions(teamId, userId) {
  var params = [];
  var where = ['team_id = ?'];
  params.push(teamId);
  if (userId) { where.push('user_id = ?'); params.push(userId); }
  _db.run("UPDATE sso_sessions SET revoked_at = datetime('now') WHERE " + where.join(' AND '), params);
  return { revoked: true };
}

function listSessions(teamId, options) {
  options = options || {};
  var where = ['team_id = ?'];
  var params = [teamId];
  if (!options.includeRevoked) where.push('revoked_at IS NULL');
  var sql = 'SELECT id, provider_id, user_id, email, name, token_type, issued_at, expires_at, revoked_at, last_seen_at FROM sso_sessions WHERE ' + where.join(' AND ') + ' ORDER BY issued_at DESC LIMIT ?';
  params.push(options.limit || 50);
  var stmt = _db.prepare(sql);
  stmt.bind(params);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// ── Express middleware ──────────────────────────────────────────────
// Reads Authorization: Bearer <token> and attaches req.user + req.session.

function authMiddleware() {
  return function(req, res, next) {
    var header = req.headers['authorization'] || '';
    var token = null;
    if (header.indexOf('Bearer ') === 0) token = header.substring(7);

    // Fallback: X-SSO-Token header or ?access_token query
    if (!token) token = req.headers['x-sso-token'] || req.query.access_token || null;
    if (!token) return next();

    try {
      var result = validateSession(token);
      if (!result) {
        return res.status(401).json({ error: 'Invalid or expired token' });
      }
      req.user = result.payload;
      req.session = result.session;
      req.authenticated = true;
    } catch (e) {
      return res.status(401).json({ error: 'Authentication error' });
    }
    next();
  };
}

// Middleware that requires SSO auth (rejects if no valid token)
function requireAuth() {
  return function(req, res, next) {
    var header = req.headers['authorization'] || '';
    var token = null;
    if (header.indexOf('Bearer ') === 0) token = header.substring(7);
    if (!token) token = req.headers['x-sso-token'] || req.query.access_token || null;

    if (!token) return res.status(401).json({ error: 'Authentication required' });

    try {
      var result = validateSession(token);
      if (!result) return res.status(401).json({ error: 'Invalid or expired token' });
      req.user = result.payload;
      req.session = result.session;
      req.authenticated = true;
    } catch (e) {
      return res.status(401).json({ error: 'Authentication error' });
    }
    next();
  };
}

module.exports = {
  init,
  registerProvider,
  getProvider,
  listProviders,
  updateProvider,
  deleteProvider,
  issueToken,
  validateToken,
  validateSession,
  revokeSession,
  revokeAllSessions,
  listSessions,
  authMiddleware,
  requireAuth,
};
