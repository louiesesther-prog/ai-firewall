// ── Team Management Routes ────────────────────────────────────────
// Express router for team CRUD, member management, and role-based access.

const express = require('express');
const teams = require('../auth/teams.cjs');

function createTeamRoutes(database) {
  var router = express.Router();
  teams.init(database);

  // ── POST /teams — Create a new team ─────────────────────────
  router.post('/', function(req, res) {
    try {
      var body = req.body || {};
      if (!body.name) return res.status(400).json({ error: 'name required' });

      var team = teams.createTeam({
        name: body.name,
        slug: body.slug,
        plan: body.plan,
        settings: body.settings,
        creatorId: req.headers['x-user-id'] || body.creatorId,
        creatorEmail: req.headers['x-user-email'] || body.creatorEmail,
      });

      res.json({ team: team });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /teams — List all teams ─────────────────────────────
  router.get('/', function(req, res) {
    try {
      var teamList = teams.listTeams({
        plan: req.query.plan || null,
        limit: parseInt(req.query.limit, 10) || 50,
      });
      res.json({ teams: teamList });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /teams/:id — Get team details ───────────────────────
  router.get('/:id', function(req, res) {
    try {
      var team = teams.getTeam(req.params.id);
      if (!team) return res.status(404).json({ error: 'Team not found' });
      var members = teams.listMembers(req.params.id);
      res.json({ team: team, members: members });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── PATCH /teams/:id — Update team ──────────────────────────
  router.patch('/:id', function(req, res) {
    try {
      var body = req.body || {};
      var team = teams.updateTeam(req.params.id, {
        name: body.name,
        plan: body.plan,
        settings: body.settings,
      });
      if (!team) return res.status(404).json({ error: 'Team not found' });
      res.json({ team: team });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── DELETE /teams/:id — Delete team ─────────────────────────
  router.delete('/:id', function(req, res) {
    try {
      // Only admins can delete
      var userId = req.headers['x-user-id'];
      if (userId && !teams.hasRole(req.params.id, userId, 'admin')) {
        return res.status(403).json({ error: 'Admin role required' });
      }
      teams.deleteTeam(req.params.id);
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /teams/:id/members — Add member ────────────────────
  router.post('/:id/members', function(req, res) {
    try {
      var body = req.body || {};
      if (!body.userId) return res.status(400).json({ error: 'userId required' });

      var result = teams.addMember(req.params.id, body.userId, {
        email: body.email,
        role: body.role,
        invitedBy: req.headers['x-user-id'] || null,
      });

      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /teams/:id/members — List members ───────────────────
  router.get('/:id/members', function(req, res) {
    try {
      var members = teams.listMembers(req.params.id);
      res.json({ members: members });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── PATCH /teams/:id/members/:userId — Update role ──────────
  router.patch('/:id/members/:userId', function(req, res) {
    try {
      var body = req.body || {};
      if (!body.role) return res.status(400).json({ error: 'role required (admin/member/viewer)' });

      var valid = ['admin', 'member', 'viewer'];
      if (valid.indexOf(body.role) === -1) {
        return res.status(400).json({ error: 'Invalid role. Must be: admin, member, or viewer' });
      }

      var member = teams.updateMemberRole(req.params.id, req.params.userId, body.role);
      if (!member) return res.status(404).json({ error: 'Member not found' });
      res.json({ member: member });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── DELETE /teams/:id/members/:userId — Remove member ───────
  router.delete('/:id/members/:userId', function(req, res) {
    try {
      teams.removeMember(req.params.id, req.params.userId);
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /teams/slug/:slug — Get team by slug ────────────────
  router.get('/slug/:slug', function(req, res) {
    try {
      var team = teams.getTeamBySlug(req.params.slug);
      if (!team) return res.status(404).json({ error: 'Team not found' });
      res.json({ team: team });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = createTeamRoutes;
