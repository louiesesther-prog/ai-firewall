// ── RBAC / Permissions Routes ────────────────────────────────────────
// Inspect & grant/deny member permissions, list permissions, seed.

const express = require('express');
const rbac = require('../auth/rbac.cjs');

function createRbacRoutes(database) {
  var router = express.Router();
  rbac.init(database);

  // ── POST /rbac/seed — ensure default permissions & role mappings ──
  router.post('/seed', function(req, res) {
    try {
      rbac.ensureSeedPermissions();
      res.json({ seeded: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /rbac/permissions — list all known permissions ─────────
  router.get('/permissions', function(req, res) {
    try {
      var stmt = database.prepare('SELECT DISTINCT resource FROM permissions ORDER BY resource');
      var resources = [];
      while (stmt.step()) resources.push(stmt.getAsObject().resource);
      stmt.free();

      var all = [];
      for (var i = 0; i < resources.length; i++) {
        var s = database.prepare('SELECT name, action, description FROM permissions WHERE resource = ? ORDER BY action');
        s.bind([resources[i]]);
        var perms = [];
        while (s.step()) {
          var r = s.getAsObject();
          perms.push({ name: r.name, action: r.action, description: r.description });
        }
        s.free();
        all.push({ resource: resources[i], permissions: perms });
      }
      res.json({ resources: all });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /rbac/roles — default role→permission matrix ──────────
  router.get('/roles', function(req, res) {
    try {
      var roles = rbac.DEFAULT_ROLE_PERMISSIONS || {};
      res.json({ roles: roles });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /rbac/:teamId/user/:userId — resolved permissions for user
  router.get('/:teamId/user/:userId', function(req, res) {
    try {
      var resolved = rbac.getPermissions(req.params.teamId, req.params.userId);
      var overrides = rbac.listMemberPermissions(req.params.teamId, req.params.userId);
      res.json({ teamId: req.params.teamId, userId: req.params.userId, role: resolved.role, permissions: resolved.permissions, overrides: overrides });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /rbac/:teamId/user/:userId/:permission — check a permission
  router.get('/:teamId/user/:userId/has/:permission', function(req, res) {
    try {
      var allowed = rbac.hasPermission(req.params.teamId, req.params.userId, req.params.permission);
      res.json({ teamId: req.params.teamId, userId: req.params.userId, permission: req.params.permission, allowed: allowed });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── PUT /rbac/:teamId/user/:userId/:permission — grant/deny/clear
  // body: { granted: true } or { clears: true }
  router.put('/:teamId/user/:userId/:permission', function(req, res) {
    try {
      var body = req.body || {};
      if (body.clears) {
        rbac.clearMemberPermission(req.params.teamId, req.params.userId, req.params.permission);
        return res.json({ cleared: true });
      }
      var result = rbac.setMemberPermission(req.params.teamId, req.params.userId, req.params.permission, !!body.granted);
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = createRbacRoutes;
