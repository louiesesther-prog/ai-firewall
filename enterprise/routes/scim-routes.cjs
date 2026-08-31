// ── SCIM Routes ─────────────────────────────────────────────────────
// SCIM 2.0 user & group provisioning endpoints (subset of the spec).

const express = require('express');
const scim = require('../identity/scim.cjs');

function createScimRoutes(database) {
  var router = express.Router();
  scim.init(database);

  // ── Users ────────────────────────────────────────────────────

  // POST /scim/v2/Users — create user
  router.post('/v2/Users', function(req, res) {
    try {
      var body = req.body || {};
      var teamId = body['x-team-id'] || req.headers['x-team-id'];
      var user = scim.createUser(teamId, body);
      res.status(201).json(user);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /scim/v2/Users — list users
  router.get('/v2/Users', function(req, res) {
    try {
      var teamId = req.query.teamId || req.headers['x-team-id'];
      var result = scim.listUsers(teamId, { count: req.query.count, startIndex: req.query.startIndex });
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /scim/v2/Users/:id — get user
  router.get('/v2/Users/:id', function(req, res) {
    try {
      var user = scim.getUser(req.params.id);
      if (!user) return res.status(404).json({ error: 'User not found' });
      res.json(user);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // PUT /scim/v2/Users/:id — full update
  router.put('/v2/Users/:id', function(req, res) {
    try {
      var user = scim.updateUser(req.params.id, req.body || {}, false);
      if (!user) return res.status(404).json({ error: 'User not found' });
      res.json(user);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // PATCH /scim/v2/Users/:id — partial update
  router.patch('/v2/Users/:id', function(req, res) {
    try {
      var user = scim.updateUser(req.params.id, req.body || {}, true);
      if (!user) return res.status(404).json({ error: 'User not found' });
      res.json(user);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // DELETE /scim/v2/Users/:id — soft delete
  router.delete('/v2/Users/:id', function(req, res) {
    try {
      scim.deleteUser(req.params.id);
      res.status(204).send();
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── Groups ───────────────────────────────────────────────────

  // POST /scim/v2/Groups — create group
  router.post('/v2/Groups', function(req, res) {
    try {
      var body = req.body || {};
      var teamId = body['x-team-id'] || req.headers['x-team-id'];
      var group = scim.createGroup(teamId, body);
      res.status(201).json(group);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /scim/v2/Groups — list groups
  router.get('/v2/Groups', function(req, res) {
    try {
      var teamId = req.query.teamId || req.headers['x-team-id'];
      res.json(scim.listGroups(teamId));
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /scim/v2/Groups/:id — get group
  router.get('/v2/Groups/:id', function(req, res) {
    try {
      var group = scim.getGroup(req.params.id);
      if (!group) return res.status(404).json({ error: 'Group not found' });
      res.json(group);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // PUT /scim/v2/Groups/:id — full update (replace members)
  router.put('/v2/Groups/:id', function(req, res) {
    try {
      var group = scim.updateGroup(req.params.id, req.body || {}, false);
      if (!group) return res.status(404).json({ error: 'Group not found' });
      res.json(group);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // PATCH /scim/v2/Groups/:id — partial update
  router.patch('/v2/Groups/:id', function(req, res) {
    try {
      var group = scim.updateGroup(req.params.id, req.body || {}, true);
      if (!group) return res.status(404).json({ error: 'Group not found' });
      res.json(group);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // DELETE /scim/v2/Groups/:id — delete group
  router.delete('/v2/Groups/:id', function(req, res) {
    try {
      scim.deleteGroup(req.params.id);
      res.status(204).send();
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── ServiceProviderConfig (SCIM discovery) ───────────────────
  router.get('/v2/ServiceProviderConfig', function(req, res) {
    res.json({
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
      patch: { supported: true },
      bulk: { supported: false },
      filter: { supported: false },
      etag: { supported: false },
      sort: { supported: false },
      changePassword: { supported: false },
      authenticationSchemes: [{ type: 'oauthBearerToken', name: 'OAuth Bearer Token' }],
    });
  });

  // ── ResourceTypes + Schemas (discovery) ──────────────────────
  router.get('/v2/ResourceTypes', function(req, res) {
    res.json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      totalResults: 2,
      Resources: [
        { schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'], id: 'User', name: 'User', endpoint: '/v2/Users', schema: 'urn:ietf:params:scim:schemas:core:2.0:User' },
        { schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'], id: 'Group', name: 'Group', endpoint: '/v2/Groups', schema: 'urn:ietf:params:scim:schemas:core:2.0:Group' },
      ],
    });
  });

  return router;
}

module.exports = createScimRoutes;
