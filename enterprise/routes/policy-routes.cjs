// ── Policy / Data Guardrails Routes ─────────────────────────────────
// Policy CRUD + evaluation endpoint + policy event log.

const express = require('express');
const policy = require('../policy/policy-engine.cjs');

function createPolicyRoutes(database) {
  var router = express.Router();
  policy.init(database);

  // ── POST /policies — Create a policy ─────────────────────────
  router.post('/', function(req, res) {
    try {
      var body = req.body || {};
      body.teamId = body.teamId || req.headers['x-team-id'] || null;
      var p = policy.createPolicy(body);
      res.status(201).json({ policy: p });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /policies — List policies ────────────────────────────
  router.get('/', function(req, res) {
    try {
      var teamId = req.query.teamId || req.headers['x-team-id'] || null;
      var policies = policy.listPolicies(teamId, { includeDisabled: req.query.includeDisabled === 'true' });
      res.json({ policies: policies });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /policies/:id — Get policy ───────────────────────────
  router.get('/:id', function(req, res) {
    try {
      var p = policy.getPolicy(req.params.id);
      if (!p) return res.status(404).json({ error: 'Policy not found' });
      res.json({ policy: p });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── PATCH /policies/:id — Update policy ──────────────────────
  router.patch('/:id', function(req, res) {
    try {
      var p = policy.updatePolicy(req.params.id, req.body || {});
      if (!p) return res.status(404).json({ error: 'Policy not found' });
      res.json({ policy: p });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── DELETE /policies/:id — Delete policy ─────────────────────
  router.delete('/:id', function(req, res) {
    try {
      policy.deletePolicy(req.params.id);
      res.json({ deleted: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /policies/evaluate — Test/evaluate content ──────────
  router.post('/evaluate', function(req, res) {
    try {
      var body = req.body || {};
      var context = {
        teamId: body.teamId || req.headers['x-team-id'] || null,
        userId: body.userId || req.headers['x-user-id'] || null,
        scope: body.scope || '*',
        channel: body.channel || 'all',
        text: body.text,
        piiTypes: body.piiTypes,
        riskScore: body.riskScore,
        source: body.source || 'api',
      };
      var decision = policy.evaluate(context);
      res.json(decision);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /policies/events — Policy enforcement log ────────────
  router.get('/events', function(req, res) {
    try {
      var teamId = req.query.teamId || req.headers['x-team-id'] || null;
      var events = policy.getPolicyEvents(teamId, { limit: parseInt(req.query.limit, 10) || 50 });
      res.json({ events: events });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = createPolicyRoutes;
