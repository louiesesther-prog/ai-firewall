// ── Multi-Tenancy (Organizations) ───────────────────────────────────
// Organizations own multiple teams. Provides org CRUD, org membership,
// team↔org linking, and tenant-scoping helpers that ensure a query stays
// within an org/team boundary (cross-tenant isolation at the data layer).

var _db = null;

function init(database) {
  _db = database;
}

function _slugify(name) {
  return String(name || 'org').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

// ── Org CRUD ─────────────────────────────────────────────────────────

function createOrganization(options) {
  options = options || {};
  var id = 'org_' + Date.now().toString(36) + '_' + require('crypto').randomBytes(4).toString('hex');
  var slug = options.slug || _slugify(options.name) + '_' + id.substring(4, 8);

  _db.run(
    `INSERT INTO organizations (id, name, slug, plan, status, settings, created_by)
     VALUES (?, ?, ?, ?, 'active', ?, ?)`,
    [id, options.name || 'Organization', slug, options.plan || 'free',
     typeof options.settings === 'string' ? options.settings : JSON.stringify(options.settings || {}),
     options.createdBy || null]
  );

  if (options.creatorId) {
    _db.run(
      `INSERT INTO org_members (org_id, user_id, email, role, invited_by) VALUES (?, ?, ?, 'owner', ?)`,
      [id, options.creatorId, options.creatorEmail || null, id]
    );
  }

  return getOrganization(id);
}

function getOrganization(id) {
  var stmt = _db.prepare('SELECT * FROM organizations WHERE id = ?');
  stmt.bind([id]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  return row;
}

function getOrganizationBySlug(slug) {
  var stmt = _db.prepare('SELECT * FROM organizations WHERE slug = ?');
  stmt.bind([slug]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  return row;
}

function listOrganizations(options) {
  options = options || {};
  var sql = 'SELECT * FROM organizations';
  var params = [];
  if (options.plan) { sql += ' WHERE plan = ?'; params.push(options.plan); }
  sql += ' ORDER BY created_at DESC';
  if (options.limit) { sql += ' LIMIT ?'; params.push(options.limit); }
  var stmt = _db.prepare(sql);
  if (params.length) stmt.bind(params);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function updateOrganization(id, updates) {
  var sets = [];
  var params = [];
  if (updates.name !== undefined) { sets.push('name = ?'); params.push(updates.name); }
  if (updates.plan !== undefined) { sets.push('plan = ?'); params.push(updates.plan); }
  if (updates.status !== undefined) { sets.push('status = ?'); params.push(updates.status); }
  if (updates.settings !== undefined) {
    sets.push('settings = ?');
    params.push(typeof updates.settings === 'string' ? updates.settings : JSON.stringify(updates.settings));
  }
  if (sets.length === 0) return getOrganization(id);
  sets.push("updated_at = datetime('now')");
  params.push(id);
  _db.run('UPDATE organizations SET ' + sets.join(', ') + ' WHERE id = ?', params);
  return getOrganization(id);
}

function deleteOrganization(id) {
  _db.run('DELETE FROM organizations WHERE id = ?', [id]);
  return { deleted: true };
}

// ── Org membership ───────────────────────────────────────────────────

function addOrgMember(orgId, userId, options) {
  options = options || {};
  try {
    _db.run(
      `INSERT INTO org_members (org_id, user_id, email, role, invited_by) VALUES (?, ?, ?, ?, ?)`,
      [orgId, userId, options.email || null, options.role || 'member', options.invitedBy || null]
    );
    return { added: true };
  } catch (e) {
    _db.run('UPDATE org_members SET role = ? WHERE org_id = ? AND user_id = ?',
      [options.role || 'member', orgId, userId]);
    return { updated: true };
  }
}

function getOrgMember(orgId, userId) {
  var stmt = _db.prepare('SELECT * FROM org_members WHERE org_id = ? AND user_id = ?');
  stmt.bind([orgId, userId]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  return row;
}

function listOrgMembers(orgId) {
  var stmt = _db.prepare('SELECT * FROM org_members WHERE org_id = ? ORDER BY joined_at ASC');
  stmt.bind([orgId]);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function removeOrgMember(orgId, userId) {
  _db.run('DELETE FROM org_members WHERE org_id = ? AND user_id = ?', [orgId, userId]);
  return { removed: true };
}

// ── Team ↔ Org linking ───────────────────────────────────────────────

function addTeamToOrg(orgId, teamId) {
  _db.run('INSERT OR IGNORE INTO org_teams (org_id, team_id) VALUES (?, ?)', [orgId, teamId]);
  return { linked: true };
}

function removeTeamFromOrg(orgId, teamId) {
  _db.run('DELETE FROM org_teams WHERE org_id = ? AND team_id = ?', [orgId, teamId]);
  return { unlinked: true };
}

function listOrgTeams(orgId) {
  var stmt = _db.prepare(
    'SELECT t.* FROM teams t INNER JOIN org_teams ot ON t.id = ot.team_id WHERE ot.org_id = ? ORDER BY t.created_at DESC'
  );
  stmt.bind([orgId]);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// Given a team id, find its owning org (for tenant boundary checks)
function getOrgForTeam(teamId) {
  var stmt = _db.prepare(
    'SELECT o.* FROM organizations o INNER JOIN org_teams ot ON o.id = ot.org_id WHERE ot.team_id = ?'
  );
  stmt.bind([teamId]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  return row;
}

// Given an org id, return the list of team ids under it
function getTeamIdsForOrg(orgId) {
  var stmt = _db.prepare('SELECT team_id FROM org_teams WHERE org_id = ?');
  stmt.bind([orgId]);
  var ids = [];
  while (stmt.step()) ids.push(stmt.getAsObject().team_id);
  stmt.free();
  return ids;
}

// Orgs a user belongs to (as a member)
function getOrgsForUser(userId) {
  var stmt = _db.prepare(
    'SELECT o.* FROM organizations o INNER JOIN org_members om ON o.id = om.org_id WHERE om.user_id = ? ORDER BY om.joined_at ASC'
  );
  stmt.bind([userId]);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// Does the user have an org-level role >= minRole in this org?
function hasOrgRole(orgId, userId, minRole) {
  var member = getOrgMember(orgId, userId);
  if (!member) return false;
  var hierarchy = { owner: 4, admin: 3, member: 2, viewer: 1 };
  return (hierarchy[member.role] || 0) >= (hierarchy[minRole] || 0);
}

// ── Tenant scoping helpers ───────────────────────────────────────────
// Build a WHERE fragment + params that restrict a query to a tenant.
// scopeBy: 'org' (all org teams) or 'team' (single team).
function scopeTeams(teamId, orgId) {
  var where = [];
  var params = [];
  if (orgId) {
    var ids = getTeamIdsForOrg(orgId);
    if (ids.length === 0) {
      where.push('1 = 0'); // no teams -> match nothing
    } else {
      where.push('team_id IN (' + ids.map(function() { return '?'; }).join(',') + ')');
      params = params.concat(ids);
    }
  } else if (teamId) {
    where.push('team_id = ?');
    params.push(teamId);
  }
  return { where: where, params: params };
}

function scopeByUser(teamId, userId) {
  var where = [];
  var params = [];
  if (teamId) { where.push('team_id = ?'); params.push(teamId); }
  if (userId) { where.push('user_id = ?'); params.push(userId); }
  return { where: where, params: params };
}

module.exports = {
  init,
  createOrganization,
  getOrganization,
  getOrganizationBySlug,
  listOrganizations,
  updateOrganization,
  deleteOrganization,
  addOrgMember,
  getOrgMember,
  listOrgMembers,
  removeOrgMember,
  addTeamToOrg,
  removeTeamFromOrg,
  listOrgTeams,
  getOrgForTeam,
  getTeamIdsForOrg,
  getOrgsForUser,
  hasOrgRole,
  scopeTeams,
  scopeByUser,
};
