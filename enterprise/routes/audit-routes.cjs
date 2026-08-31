// ── Audit API Routes ──────────────────────────────────────────────
// Express router for audit trail, compliance export, and retention.

const express = require('express');
const audit = require('../audit/audit.cjs');
const complianceExport = require('../audit/compliance-export.cjs');
const retention = require('../audit/retention.cjs');

function createAuditRoutes(database) {
  var router = express.Router();

  audit.init(database);
  complianceExport.init(database);
  retention.init(database);

  // ── GET /audit/events ────────────────────────────────────────
  router.get('/events', function(req, res) {
    try {
      var events = audit.getEvents({
        teamId: req.query.teamId || null,
        userId: req.query.userId || null,
        action: req.query.action || null,
        from: req.query.from || null,
        to: req.query.to || null,
        limit: parseInt(req.query.limit, 10) || 100,
      });
      var total = audit.getEventCount({
        teamId: req.query.teamId || null,
        userId: req.query.userId || null,
        action: req.query.action || null,
        from: req.query.from || null,
        to: req.query.to || null,
      });
      res.json({ events: events, total: total });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /audit/events/count ──────────────────────────────────
  router.get('/events/count', function(req, res) {
    try {
      var count = audit.getEventCount({
        teamId: req.query.teamId || null,
        userId: req.query.userId || null,
        action: req.query.action || null,
        from: req.query.from || null,
        to: req.query.to || null,
      });
      res.json({ count: count });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /audit/export ────────────────────────────────────────
  router.get('/export', function(req, res) {
    try {
      var reports = complianceExport.listReports({
        teamId: req.query.teamId || null,
        reportType: req.query.type || null,
        limit: parseInt(req.query.limit, 10) || 50,
      });
      res.json({ reports: reports });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /audit/export ───────────────────────────────────────
  router.post('/export', function(req, res) {
    try {
      var body = req.body || {};
      if (!body.reportType) return res.status(400).json({ error: 'reportType required (soc2, gdpr_art30, hipaa)' });
      if (!body.periodStart || !body.periodEnd) return res.status(400).json({ error: 'periodStart and periodEnd required (ISO date strings)' });

      var report = complianceExport.generateReport({
        reportType: body.reportType,
        teamId: body.teamId || null,
        periodStart: body.periodStart,
        periodEnd: body.periodEnd,
        generatedBy: body.generatedBy || 'api',
        controller: body.controller || null,
        processor: body.processor || null,
        recipients: body.recipients || null,
        retentionDays: body.retentionDays || null,
        crossBorderTransfers: body.crossBorderTransfers || null,
        entity: body.entity || null,
        businessAssociates: body.businessAssociates || null,
      });

      res.json({ report: report });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /audit/export/:id ────────────────────────────────────
  router.get('/export/:id', function(req, res) {
    try {
      var reports = complianceExport.listReports({ limit: 1000 });
      var report = reports.find(function(r) { return r.id === req.params.id; });
      if (!report) return res.status(404).json({ error: 'Report not found' });
      res.json({ report: report });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /audit/retention ─────────────────────────────────────
  router.get('/retention', function(req, res) {
    try {
      var stats = retention.getRetentionStats();
      res.json({ stats: stats, defaultRetentionDays: 365 });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /audit/retention/cleanup ────────────────────────────
  router.post('/retention/cleanup', function(req, res) {
    try {
      var body = req.body || {};
      var result = retention.cleanupExpired(body.retentionDays || 365);
      res.json({ result: result });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = createAuditRoutes;
