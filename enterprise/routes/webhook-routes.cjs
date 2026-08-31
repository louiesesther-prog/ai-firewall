// ── Webhook API Routes ────────────────────────────────────────────
// Express router for webhook configuration and delivery tracking.

const express = require('express');
const crypto = require('crypto');
const webhooks = require('../integrations/webhooks.cjs');

function createWebhookRoutes(database) {
  var router = express.Router();

  webhooks.init(database);

  // ── GET /webhooks ────────────────────────────────────────────
  router.get('/', function(req, res) {
    try {
      var where = [];
      var params = [];
      if (req.query.teamId) { where.push('team_id = ?'); params.push(req.query.teamId); }

      var sql = 'SELECT id, team_id, name, url, events, enabled, failure_count, last_triggered_at, created_at FROM webhooks';
      if (where.length) sql += ' WHERE ' + where.join(' AND ');
      sql += ' ORDER BY created_at DESC';

      var stmt = database.prepare(sql);
      if (params.length) stmt.bind(params);
      var rows = [];
      while (stmt.step()) rows.push(stmt.getAsObject());
      stmt.free();

      res.json({ webhooks: rows });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /webhooks ───────────────────────────────────────────
  router.post('/', function(req, res) {
    try {
      var body = req.body || {};
      if (!body.name) return res.status(400).json({ error: 'name required' });
      if (!body.url) return res.status(400).json({ error: 'url required' });
      if (!body.events) return res.status(400).json({ error: 'events required (JSON array)' });

      var id = 'wh_' + Date.now().toString(36) + '_' + crypto.randomBytes(4).toString('hex');
      var secret = body.secret || crypto.randomBytes(32).toString('hex');
      var events = typeof body.events === 'string' ? body.events : JSON.stringify(body.events);
      var headers = body.headers ? (typeof body.headers === 'string' ? body.headers : JSON.stringify(body.headers)) : '{}';

      database.run(
        `INSERT INTO webhooks (id, team_id, name, url, secret, events, headers, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [id, body.teamId || null, body.name, body.url, secret, events, headers, body.enabled !== false ? 1 : 0]
      );

      res.json({ webhook: { id: id, name: body.name, url: body.url, events: events, secret: secret } });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── DELETE /webhooks/:id ─────────────────────────────────────
  router.delete('/:id', function(req, res) {
    try {
      database.run('DELETE FROM webhooks WHERE id = ?', [req.params.id]);
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /webhooks/:id/test ──────────────────────────────────
  router.post('/:id/test', function(req, res) {
    try {
      var stmt = database.prepare('SELECT * FROM webhooks WHERE id = ?');
      stmt.bind([req.params.id]);
      var webhook = null;
      if (stmt.step()) webhook = stmt.getAsObject();
      stmt.free();

      if (!webhook) return res.status(404).json({ error: 'Webhook not found' });

      webhooks.deliverWebhook(webhook, 'test', {
        message: 'AI Firewall webhook test',
        timestamp: new Date().toISOString(),
      });

      res.json({ success: true, message: 'Test event dispatched' });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /webhooks/deliveries ─────────────────────────────────
  router.get('/deliveries', function(req, res) {
    try {
      var deliveries = webhooks.getDeliveries({
        webhookId: req.query.webhookId || null,
        status: req.query.status || null,
        limit: parseInt(req.query.limit, 10) || 50,
      });
      res.json({ deliveries: deliveries });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = createWebhookRoutes;
