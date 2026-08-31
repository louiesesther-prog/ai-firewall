// ── Network Agent Routes ────────────────────────────────────────────
// Record connections + payload analysis + summary + status.

const express = require('express');
const agent = require('../observability/network-agent.cjs');

function createNetworkRoutes(database) {
  var router = express.Router();
  agent.init(database);

  // ── GET /network/status — Agent status ───────────────────────
  router.get('/status', function(req, res) {
    res.json({ module: 'network-agent', status: agent.getStatus() });
  });

  // ── POST /network/status — Set agent status ──────────────────
  router.post('/status', function(req, res) {
    agent.setStatus((req.body || {}).status);
    res.json({ status: agent.getStatus() });
  });

  // ── POST /network/connection — Record a connection ───────────
  router.post('/connection', function(req, res) {
    try {
      var body = req.body || {};
      // Auto-analyze payload if provided
      var pii = { piiTypes: body.piiTypes || [], riskScore: body.riskScore || 0 };
      if (body.payload && !body.piiTypes) {
        pii = agent.analyzePayload(body.payload);
      }
      var result = agent.recordConnection({
        teamId: body.teamId || req.headers['x-team-id'] || null,
        sourceIp: body.sourceIp || body.srcIp,
        destIp: body.destIp || body.dstIp,
        destPort: body.destPort || body.dstPort,
        protocol: body.protocol,
        domain: body.domain,
        domainName: body.domainName,
        aiService: body.aiService,
        connectionType: body.connectionType,
        payload: body.payload,
        piiTypes: pii.piiTypes,
        riskScore: pii.riskScore,
        actionTaken: body.actionTaken || 'observed',
        metadata: body.metadata || {},
      });
      res.status(201).json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /network/analyze — Analyze a payload for PII ────────
  router.post('/analyze', function(req, res) {
    try {
      var payload = (req.body || {}).payload || '';
      res.json(agent.analyzePayload(payload));
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /network/events — List network events ────────────────
  router.get('/events', function(req, res) {
    try {
      var teamId = req.query.teamId || req.headers['x-team-id'] || null;
      var events = agent.listEvents(teamId, {
        aiService: req.query.aiService,
        sourceIp: req.query.sourceIp,
        limit: parseInt(req.query.limit, 10) || 100,
      });
      res.json({ events: events });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /network/summary — Summary stats ─────────────────────
  router.get('/summary', function(req, res) {
    try {
      var teamId = req.query.teamId || req.headers['x-team-id'] || null;
      res.json(agent.getSummary(teamId));
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = createNetworkRoutes;
