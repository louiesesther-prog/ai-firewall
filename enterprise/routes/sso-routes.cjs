// ── SSO Routes ──────────────────────────────────────────────────────
// Provider management + token issuance + session management + auth.

const express = require('express');
const sso = require('../identity/sso.cjs');

function createSsoRoutes(database) {
  var router = express.Router();
  sso.init(database);

  // ── POST /sso/providers — Register an SSO provider ──────────
  router.post('/providers', function(req, res) {
    try {
      var body = req.body || {};
      var teamId = body.teamId || req.headers['x-team-id'];
      if (!teamId) return res.status(400).json({ error: 'teamId required' });
      var provider = sso.registerProvider(teamId, body);
      res.status(201).json({ provider: provider });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /sso/providers — List providers ─────────────────────
  router.get('/providers', function(req, res) {
    try {
      var teamId = req.query.teamId || req.headers['x-team-id'];
      if (!teamId) return res.status(400).json({ error: 'teamId required' });
      res.json({ providers: sso.listProviders(teamId) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── PATCH /sso/providers/:id — Update provider ──────────────
  router.patch('/providers/:id', function(req, res) {
    try {
      var provider = sso.updateProvider(req.params.id, req.body || {});
      if (!provider) return res.status(404).json({ error: 'Provider not found' });
      res.json({ provider: provider });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── DELETE /sso/providers/:id — Delete provider ─────────────
  router.delete('/providers/:id', function(req, res) {
    try {
      sso.deleteProvider(req.params.id);
      res.json({ deleted: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /sso/token — Issue an SSO token (IdP) ──────────────
  router.post('/token', function(req, res) {
    try {
      var body = req.body || {};
      var teamId = body.teamId || req.headers['x-team-id'];
      if (!teamId) return res.status(400).json({ error: 'teamId required' });

      var token = sso.issueToken(teamId, {
        subject: body.userId || body.subject,
        email: body.email,
        name: body.name,
        scopes: body.scopes,
        ttlSeconds: body.ttlSeconds,
        providerId: body.providerId || null,
        issuer: body.issuer,
        audience: body.audience,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] || null,
        metadata: body.metadata,
      });
      res.json(token);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /sso/verify — Validate a token ─────────────────────
  router.post('/verify', function(req, res) {
    try {
      var token = (req.body || {}).token;
      if (!token) return res.status(400).json({ error: 'token required' });
      var result = sso.validateSession(token);
      if (!result) return res.status(401).json({ valid: false, error: 'Invalid or expired token' });
      res.json({ valid: true, user: result.payload, session: result.session });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /sso/sessions — List sessions ───────────────────────
  router.get('/sessions', function(req, res) {
    try {
      var teamId = req.query.teamId || req.headers['x-team-id'];
      if (!teamId) return res.status(400).json({ error: 'teamId required' });
      res.json({ sessions: sso.listSessions(teamId, { includeRevoked: req.query.includeRevoked === 'true' }) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /sso/sessions/:id/revoke — Revoke a session ───────
  router.post('/sessions/:id/revoke', function(req, res) {
    try {
      sso.revokeSession(req.params.id);
      res.json({ revoked: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /sso/:id/status — Active status (keep-alive) ───────
  router.get('/health', function(req, res) {
    res.json({ status: 'ok', module: 'sso' });
  });

  return router;
}

module.exports = createSsoRoutes;
