// ── API Key Routes ────────────────────────────────────────────────
// Express router for API key CRUD, validation, rotation, and usage.

const express = require('express');
const apiKeys = require('../auth/api-keys.cjs');

function createApiKeyRoutes(database) {
  var router = express.Router();
  apiKeys.init(database);

  // ── POST /api-keys — Generate new API key ───────────────────
  router.post('/', function(req, res) {
    try {
      var body = req.body || {};
      var teamId = body.teamId || req.headers['x-team-id'];
      if (!teamId) return res.status(400).json({ error: 'teamId required' });

      var key = apiKeys.generateKey(teamId, {
        name: body.name,
        scopes: body.scopes,
        rateLimit: body.rateLimit,
        quotaDaily: body.quotaDaily,
        createdBy: req.headers['x-user-id'] || null,
        expiresAt: body.expiresAt || null,
      });

      res.json({ apiKey: key });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /api-keys — List API keys for a team ────────────────
  router.get('/', function(req, res) {
    try {
      var teamId = req.query.teamId || req.headers['x-team-id'];
      if (!teamId) return res.status(400).json({ error: 'teamId required' });

      var keys = apiKeys.listKeys(teamId, {
        includeRevoked: req.query.includeRevoked === 'true',
        limit: parseInt(req.query.limit, 10) || 50,
      });

      res.json({ apiKeys: keys });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /api-keys/:id — Get single API key details ──────────
  router.get('/:id', function(req, res) {
    try {
      var key = apiKeys.getKey(req.params.id);
      if (!key) return res.status(404).json({ error: 'API key not found' });
      res.json({ apiKey: key });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── PATCH /api-keys/:id — Update API key ────────────────────
  router.patch('/:id', function(req, res) {
    try {
      var body = req.body || {};
      var key = apiKeys.updateKey(req.params.id, {
        name: body.name,
        scopes: body.scopes,
        rateLimit: body.rateLimit,
        quotaDaily: body.quotaDaily,
        enabled: body.enabled,
        expiresAt: body.expiresAt,
      });
      if (!key) return res.status(404).json({ error: 'API key not found' });
      res.json({ apiKey: key });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /api-keys/:id/revoke — Revoke an API key ──────────
  router.post('/:id/revoke', function(req, res) {
    try {
      apiKeys.revokeKey(req.params.id);
      res.json({ success: true, message: 'API key revoked' });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /api-keys/:id/rotate — Rotate an API key ──────────
  router.post('/:id/rotate', function(req, res) {
    try {
      var teamId = req.body.teamId || req.headers['x-team-id'];
      if (!teamId) return res.status(400).json({ error: 'teamId required' });

      var newKey = apiKeys.rotateKey(req.params.id, teamId);
      if (!newKey) return res.status(404).json({ error: 'API key not found or team mismatch' });
      res.json({ apiKey: newKey });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /api-keys/:id/usage — Get usage stats for a key ─────
  router.get('/:id/usage', function(req, res) {
    try {
      var usage = apiKeys.getUsage(req.params.id, {
        from: req.query.from || null,
        to: req.query.to || null,
        limit: parseInt(req.query.limit, 10) || 30,
      });
      var today = apiKeys.getUsageToday(req.params.id);
      res.json({ usage: usage, today: today });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /api-keys/:id/quota — Check quota for a key ─────────
  router.get('/:id/quota', function(req, res) {
    try {
      var result = apiKeys.checkQuota(req.params.id);
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = createApiKeyRoutes;
