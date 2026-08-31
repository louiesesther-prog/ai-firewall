// ── Multi-Tenancy / Organization Routes ─────────────────────────────
// Org CRUD, org membership, team linking, tenant summaries.

const express = require('express');
const orgs = require('../tenancy/organizations.cjs');

function createOrganizationRoutes(database) {
  var router = express.Router();
  orgs.init(database);

  // ── POST /orgs — Create organization ──────────────────────────
  router.post('/', function(req, res) {
    try {
      var body = req.body || {};
      var org = orgs.createOrganization({
        name: body.name,
        plan: body.plan,
        slug: body.slug,
        settings: body.settings,
        createdBy: body.createdBy || req.headers['x-user-id'] || null,
        creatorId: body.creatorId || req.headers['x-user-id'] || body.userId || null,
        creatorEmail: body.creatorEmail || null,
      });
      res.status(201).json({ organization: org });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /orgs — List organizations ────────────────────────────
  router.get('/', function(req, res) {
    try {
      var orgList = orgs.listOrganizations({ plan: req.query.plan, limit: parseInt(req.query.limit, 10) || 100 });
      res.json({ organizations: orgList });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /orgs/:id — Get organization + teams + members ────────
  router.get('/:id', function(req, res) {
    try {
      var org = orgs.getOrganization(req.params.id);
      if (!org) return res.status(404).json({ error: 'Organization not found' });
      res.json({
        organization: org,
        teams: orgs.listOrgTeams(org.id),
        members: orgs.listOrgMembers(org.id),
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── PATCH /orgs/:id — Update organization ─────────────────────
  router.patch('/:id', function(req, res) {
    try {
      var org = orgs.updateOrganization(req.params.id, req.body || {});
      if (!org) return res.status(404).json({ error: 'Organization not found' });
      res.json({ organization: org });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── DELETE /orgs/:id — Delete organization ────────────────────
  router.delete('/:id', function(req, res) {
    try {
      orgs.deleteOrganization(req.params.id);
      res.json({ deleted: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /orgs/:id/members — Add org member ───────────────────
  router.post('/:id/members', function(req, res) {
    try {
      var body = req.body || {};
      var result = orgs.addOrgMember(req.params.id, body.userId, {
        email: body.email,
        role: body.role || 'member',
        invitedBy: req.headers['x-user-id'] || body.invitedBy || null,
      });
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /orgs/:id/members — List org members ──────────────────
  router.get('/:id/members', function(req, res) {
    try {
      res.json({ members: orgs.listOrgMembers(req.params.id) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── DELETE /orgs/:id/members/:userId — Remove org member ──────
  router.delete('/:id/members/:userId', function(req, res) {
    try {
      orgs.removeOrgMember(req.params.id, req.params.userId);
      res.json({ removed: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /orgs/:id/teams — Link a team to org ─────────────────
  router.post('/:id/teams', function(req, res) {
    try {
      var teamId = (req.body || {}).teamId;
      if (!teamId) return res.status(400).json({ error: 'teamId required' });
      orgs.addTeamToOrg(req.params.id, teamId);
      res.json({ linked: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /orgs/:id/teams — List org teams ──────────────────────
  router.get('/:id/teams', function(req, res) {
    try {
      res.json({ teams: orgs.listOrgTeams(req.params.id) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── DELETE /orgs/:id/teams/:teamId — Unlink team from org ─────
  router.delete('/:id/teams/:teamId', function(req, res) {
    try {
      orgs.removeTeamFromOrg(req.params.id, req.params.teamId);
      res.json({ unlinked: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /orgs/by-slug/:slug — Look up org by slug ─────────────
  router.get('/by-slug/:slug', function(req, res) {
    try {
      var org = orgs.getOrganizationBySlug(req.params.slug);
      if (!org) return res.status(404).json({ error: 'Organization not found' });
      res.json({ organization: org });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /orgs/for-user/:userId — Orgs a user belongs to ───────
  router.get('/for-user/:userId', function(req, res) {
    try {
      res.json({ organizations: orgs.getOrgsForUser(req.params.userId) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = createOrganizationRoutes;
