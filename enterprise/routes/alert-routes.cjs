// ── Alerts Routes ───────────────────────────────────────────────────
// Alert rule CRUD + fire test + alert list/lifecycle + stats.

const express = require('express');
const alerts = require('../alerts/alerts.cjs');

function createAlertRoutes(database, webhookDispatcher) {
  var router = express.Router();
  alerts.init(database, webhookDispatcher);

  // ── POST /alerts/rules — Create alert rule ───────────────────
  router.post('/rules', function(req, res) {
    try {
      var body = req.body || {};
      body.teamId = body.teamId || req.headers['x-team-id'] || null;
      var rule = alerts.createRule(body);
      res.status(201).json({ rule: rule });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /alerts/rules — List rules ───────────────────────────
  router.get('/rules', function(req, res) {
    try {
      var teamId = req.query.teamId || req.headers['x-team-id'] || null;
      var rules = alerts.listRules(teamId, { includeDisabled: req.query.includeDisabled === 'true' });
      res.json({ rules: rules });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /alerts/rules/:id — Get rule ─────────────────────────
  router.get('/rules/:id', function(req, res) {
    try {
      var rule = alerts.getRule(req.params.id);
      if (!rule) return res.status(404).json({ error: 'Rule not found' });
      res.json({ rule: rule });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── PATCH /alerts/rules/:id — Update rule ────────────────────
  router.patch('/rules/:id', function(req, res) {
    try {
      var rule = alerts.updateRule(req.params.id, req.body || {});
      if (!rule) return res.status(404).json({ error: 'Rule not found' });
      res.json({ rule: rule });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── DELETE /alerts/rules/:id — Delete rule ───────────────────
  router.delete('/rules/:id', function(req, res) {
    try {
      alerts.deleteRule(req.params.id);
      res.json({ deleted: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /alerts/fire — Fire a test/trigger event ────────────
  router.post('/fire', function(req, res) {
    try {
      var body = req.body || {};
      var result = alerts.fireEvent({
        eventType: body.eventType || 'high_risk',
        teamId: body.teamId || req.headers['x-team-id'] || null,
        severity: body.severity,
        title: body.title,
        message: body.message,
        payload: body.payload || {},
        riskScore: body.riskScore,
        piiTypes: body.piiTypes,
      });
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /alerts — List alerts ────────────────────────────────
  router.get('/', function(req, res) {
    try {
      var teamId = req.query.teamId || req.headers['x-team-id'] || null;
      var alertsList = alerts.listAlerts(teamId, {
        status: req.query.status,
        limit: parseInt(req.query.limit, 10) || 50,
      });
      res.json({ alerts: alertsList });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /alerts/stats — Alert statistics ─────────────────────
  router.get('/stats', function(req, res) {
    try {
      var teamId = req.query.teamId || req.headers['x-team-id'] || null;
      res.json({ stats: alerts.getAlertStats(teamId) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── PATCH /alerts/:id — Update alert status ──────────────────
  router.patch('/:id', function(req, res) {
    try {
      var status = (req.body || {}).status || 'resolved';
      var result = alerts.updateAlertStatus(req.params.id, status, req.headers['x-user-id'] || null);
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /alerts/:id/acknowledge — Acknowledge alert ─────────
  router.post('/:id/acknowledge', function(req, res) {
    try {
      alerts.updateAlertStatus(req.params.id, 'acknowledged', req.headers['x-user-id'] || null);
      res.json({ acknowledged: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = createAlertRoutes;
