// ── Marketplace Routes ───────────────────────────────────────────────
// Rule packs (list/install/import/export) & policy templates (list/apply).

const express = require('express');
const marketplace = require('../marketplace/marketplace.cjs');
const policyEngine = require('../policy/policy-engine.cjs');

function createMarketplaceRoutes(database) {
  var router = express.Router();
  marketplace.init(database, null);
  policyEngine.init(database);

  // Seed built-ins on first access
  marketplace.seedBuiltins();

  // ── GET /marketplace/packs — List available rule packs ────────
  router.get('/packs', function(req, res) {
    try {
      var packs = marketplace.listPacks({
        category: req.query.category,
        installed: req.query.installed !== undefined ? req.query.installed === 'true' : undefined,
      });
      res.json({ packs: packs });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /marketplace/packs/:id — Get a pack with rules ───────
  router.get('/packs/:id', function(req, res) {
    try {
      var pack = marketplace.getPack(req.params.id) || marketplace.getPackBySlug(req.params.id);
      if (!pack) return res.status(404).json({ error: 'Pack not found' });
      res.json({ pack: pack });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /marketplace/packs/:id/install — Install a pack ─────
  router.post('/packs/:id/install', function(req, res) {
    try {
      var result = marketplace.installPack(req.params.id);
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /marketplace/packs/:id/uninstall — Uninstall a pack ─
  router.post('/packs/:id/uninstall', function(req, res) {
    try {
      var result = marketplace.uninstallPack(req.params.id);
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /marketplace/packs/import — Import a custom pack ────
  router.post('/packs/import', function(req, res) {
    try {
      var pack = marketplace.importPack((req.body || {}).pack);
      if (pack && pack.error) return res.status(400).json(pack);
      res.status(201).json({ pack: pack });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /marketplace/packs/:id/export — Export a pack ────────
  router.get('/packs/:id/export', function(req, res) {
    try {
      var pack = marketplace.exportPack(req.params.id);
      if (!pack) return res.status(404).json({ error: 'Pack not found' });
      res.json(pack);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /marketplace/templates — List policy templates ───────
  router.get('/templates', function(req, res) {
    try {
      res.json({ templates: marketplace.listTemplates(req.query.category) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /marketplace/templates/:id — Get a template ──────────
  router.get('/templates/:id', function(req, res) {
    try {
      var t = marketplace.getTemplate(req.params.id);
      if (!t) return res.status(404).json({ error: 'Template not found' });
      res.json({ template: t });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /marketplace/templates/:id/apply — Create policy ────
  router.post('/templates/:id/apply', function(req, res) {
    try {
      var body = req.body || {};
      var result = marketplace.applyTemplate(req.params.id, policyEngine, {
        teamId: body.teamId || req.headers['x-team-id'] || null,
        name: body.name,
        priority: body.priority,
      });
      if (result.error) return res.status(400).json(result);
      res.status(201).json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = createMarketplaceRoutes;
