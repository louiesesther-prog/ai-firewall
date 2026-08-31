// ── Advanced Reporting / Analytics Routes ───────────────────────────
// Trend dashboards, distributions, summaries, and report delivery.

const express = require('express');
const reporting = require('../analytics/advanced-reporting.cjs');

function createReportingRoutes(database, webhookDispatcher) {
  var router = express.Router();
  reporting.init(database, null, webhookDispatcher);

  function teamId(req) { return req.query.teamId || req.headers['x-team-id'] || null; }
  function period(req) { return req.query.period || '30d'; }

  // ── GET /reports/dashboard — Full consolidated dashboard ─────
  router.get('/dashboard', function(req, res) {
    try {
      res.json(reporting.dashboard(teamId(req), period(req)));
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /reports/detection-trend — Events over time ──────────
  router.get('/detection-trend', function(req, res) {
    try {
      res.json({ trend: reporting.detectionTrend(teamId(req), period(req)) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /reports/pii-types — PII type distribution ───────────
  router.get('/pii-types', function(req, res) {
    try {
      res.json({ piiTypes: reporting.piiTypeDistribution(teamId(req), period(req)) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /reports/top-services — Top AI services ──────────────
  router.get('/top-services', function(req, res) {
    try {
      res.json({ services: reporting.topAIServices(teamId(req), period(req)) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /reports/top-users — Top users by risk ───────────────
  router.get('/top-users', function(req, res) {
    try {
      res.json({ users: reporting.topUsersByRisk(teamId(req), period(req)) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /reports/policy-actions — Allow/deny/redact breakdown ─
  router.get('/policy-actions', function(req, res) {
    try {
      res.json({ actions: reporting.policyActionBreakdown(teamId(req), period(req)) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /reports/alerts — Alert severity distribution ────────
  router.get('/alerts', function(req, res) {
    try {
      res.json({ alerts: reporting.alertSeverityDistribution(teamId(req)) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /reports/usage-trend — API usage over time ───────────
  router.get('/usage-trend', function(req, res) {
    try {
      res.json({ usage: reporting.usageTrend(teamId(req), period(req)) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /reports/run — Generate + deliver a summary report ──
  router.post('/run', function(req, res) {
    try {
      var body = req.body || {};
      var report = reporting.runReport(
        body.teamId || req.headers['x-team-id'] || null,
        { period: body.period || '30d', type: body.type },
        body.deliver === false ? null : 'report'
      );
      res.json(report);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /reports/health — Tenant health / data presence ──────
  router.get('/health', function(req, res) {
    try {
      res.json(reporting.healthCheck(teamId(req)));
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /reports/summary — Markdown compliance summary ────────
  router.get('/summary', function(req, res) {
    try {
      res.json({ markdown: reporting.generateSummaryReport(teamId(req), period(req)), period: period(req) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = createReportingRoutes;
