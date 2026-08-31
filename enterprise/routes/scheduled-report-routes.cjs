// ── Scheduled Reports Routes ──────────────────────────────────────
// Express router for managing recurring compliance report schedules.

const express = require('express');
const scheduledReports = require('../audit/scheduled-reports.cjs');

function createScheduledReportRoutes(database, complianceExport, webhookDispatcher) {
  var router = express.Router();
  scheduledReports.init(database, complianceExport, webhookDispatcher);

  // Restore timers on startup
  scheduledReports.restoreTimers();

  // ── POST /scheduled-reports — Create a schedule ─────────────
  router.post('/', function(req, res) {
    try {
      var body = req.body || {};
      if (!body.reportType) return res.status(400).json({ error: 'reportType required (soc2, gdpr_art30, hipaa)' });
      if (!body.teamId && !req.headers['x-team-id']) {
        return res.status(400).json({ error: 'teamId required' });
      }

      var schedule = scheduledReports.createSchedule({
        teamId: body.teamId || req.headers['x-team-id'],
        name: body.name,
        reportType: body.reportType,
        schedule: body.schedule,
        recipients: body.recipients,
        deliveryMethod: body.deliveryMethod,
        createdBy: req.headers['x-user-id'] || null,
      });

      res.json({ schedule: schedule });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /scheduled-reports — List schedules ─────────────────
  router.get('/', function(req, res) {
    try {
      var teamId = req.query.teamId || req.headers['x-team-id'];
      var schedules = scheduledReports.listSchedules(teamId, {
        includeDisabled: req.query.includeDisabled === 'true',
      });
      res.json({ schedules: schedules });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /scheduled-reports/:id — Get schedule details ───────
  router.get('/:id', function(req, res) {
    try {
      var schedule = scheduledReports.getSchedule(req.params.id);
      if (!schedule) return res.status(404).json({ error: 'Schedule not found' });
      var history = scheduledReports.getHistory(req.params.id);
      res.json({ schedule: schedule, history: history });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── PATCH /scheduled-reports/:id — Update schedule ──────────
  router.patch('/:id', function(req, res) {
    try {
      var body = req.body || {};
      var schedule = scheduledReports.updateSchedule(req.params.id, {
        name: body.name,
        schedule: body.schedule,
        recipients: body.recipients,
        deliveryMethod: body.deliveryMethod,
        enabled: body.enabled,
      });
      if (!schedule) return res.status(404).json({ error: 'Schedule not found' });
      res.json({ schedule: schedule });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── DELETE /scheduled-reports/:id — Delete schedule ─────────
  router.delete('/:id', function(req, res) {
    try {
      scheduledReports.deleteSchedule(req.params.id);
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /scheduled-reports/:id/run — Trigger immediately ───
  router.post('/:id/run', function(req, res) {
    try {
      var result = scheduledReports.runSchedule(req.params.id);
      if (result.error) return res.status(500).json({ error: result.error });
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /scheduled-reports/:id/history — Execution history ──
  router.get('/:id/history', function(req, res) {
    try {
      var history = scheduledReports.getHistory(req.params.id, {
        limit: parseInt(req.query.limit, 10) || 10,
      });
      res.json({ history: history });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = createScheduledReportRoutes;
