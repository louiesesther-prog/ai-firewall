// ── Shadow Mode Routes ──────────────────────────────────────────────
// Observe events (log-only) + shadow AI discovery + summary.

const express = require('express');
const shadow = require('../observability/shadow-mode.cjs');

function createShadowRoutes(database) {
  var router = express.Router();
  shadow.init(database);

  // ── POST /shadow/observe — Record a shadow observation ───────
  router.post('/observe', function(req, res) {
    try {
      var body = req.body || {};
      var result = shadow.observe({
        teamId: body.teamId || req.headers['x-team-id'] || null,
        userId: body.userId || req.headers['x-user-id'] || null,
        source: body.source || 'api',
        eventType: body.eventType || 'prompt_sent',
        aiService: body.aiService,
        url: body.url,
        prompt: body.prompt,
        response: body.response,
        text: body.text,
        piiTypes: body.piiTypes || [],
        riskScore: body.riskScore || 0,
        userAgent: body.userAgent || req.headers['user-agent'],
        metadata: body.metadata || {},
      });
      res.status(201).json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /shadow/prompt — Observe a prompt (log-only) ────────
  router.post('/prompt', function(req, res) {
    try {
      var body = req.body || {};
      var result = shadow.observePrompt({
        teamId: body.teamId || req.headers['x-team-id'] || null,
        userId: body.userId || req.headers['x-user-id'] || null,
        source: body.source || 'extension',
        aiService: body.aiService,
        url: body.url,
        prompt: body.prompt || body.text,
        piiTypes: body.piiTypes || [],
        riskScore: body.riskScore || 0,
        userAgent: body.userAgent,
        metadata: body.metadata || {},
      });
      res.status(201).json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /shadow/response — Observe a response (log-only) ────
  router.post('/response', function(req, res) {
    try {
      var body = req.body || {};
      var result = shadow.observeResponse({
        teamId: body.teamId || req.headers['x-team-id'] || null,
        userId: body.userId || req.headers['x-user-id'] || null,
        source: body.source || 'extension',
        aiService: body.aiService,
        url: body.url,
        response: body.response || body.text,
        piiTypes: body.piiTypes || [],
        riskScore: body.riskScore || 0,
        userAgent: body.userAgent,
        metadata: body.metadata || {},
      });
      res.status(201).json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /shadow/events — List shadow events ──────────────────
  router.get('/events', function(req, res) {
    try {
      var teamId = req.query.teamId || req.headers['x-team-id'] || null;
      var events = shadow.listEvents(teamId, {
        aiService: req.query.aiService,
        eventType: req.query.eventType,
        limit: parseInt(req.query.limit, 10) || 100,
      });
      res.json({ events: events });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /shadow/discover — Shadow AI discovery (by service) ──
  router.get('/discover', function(req, res) {
    try {
      var teamId = req.query.teamId || req.headers['x-team-id'] || null;
      res.json({ byService: shadow.discoverShadowAI(teamId), byUser: shadow.discoverByUser(teamId) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /shadow/summary — Summary stats ──────────────────────
  router.get('/summary', function(req, res) {
    try {
      var teamId = req.query.teamId || req.headers['x-team-id'] || null;
      res.json(shadow.getSummary(teamId));
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = createShadowRoutes;
