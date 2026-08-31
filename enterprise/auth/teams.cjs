// ── Team / Organization Management ────────────────────────────────
// Create teams, manage members with roles (admin/member/viewer),
// team settings and plan management.

var _db = null;

function init(database) {
  _db = database;
}

function createTeam(options) {
  options = options || {};
  var id = 'tm_' + Date.now().toString(36) + '_' + require('crypto').randomBytes(4).toString('hex');
  var slug = options.slug || options.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

  _db.run(
    `INSERT INTO teams (id, name, slug, plan, settings) VALUES (?, ?, ?, ?, ?)`,
    [id, options.name || 'My Team', slug, options.plan || 'free', JSON.stringify(options.settings || {})]
  );

  // Add creator as admin
  if (options.creatorId) {
    _db.run(
      `INSERT INTO team_members (team_id, user_id, email, role) VALUES (?, ?, ?, 'admin')`,
      [id, options.creatorId, options.creatorEmail || null]
    );
  }

  return { id: id, name: options.name || 'My Team', slug: slug, plan: options.plan || 'free' };
}

function getTeam(id) {
  var stmt = _db.prepare('SELECT * FROM teams WHERE id = ?');
  stmt.bind([id]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  return row;
}

function getTeamBySlug(slug) {
  var stmt = _db.prepare('SELECT * FROM teams WHERE slug = ?');
  stmt.bind([slug]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  return row;
}

function listTeams(options) {
  options = options || {};
  var sql = 'SELECT * FROM teams';
  var params = [];
  if (options.plan) {
    sql += ' WHERE plan = ?';
    params.push(options.plan);
  }
  sql += ' ORDER BY created_at DESC';
  if (options.limit) { sql += ' LIMIT ?'; params.push(options.limit); }

  var stmt = _db.prepare(sql);
  if (params.length) stmt.bind(params);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function updateTeam(id, updates) {
  var sets = [];
  var params = [];
  if (updates.name !== undefined) { sets.push('name = ?'); params.push(updates.name); }
  if (updates.plan !== undefined) { sets.push('plan = ?'); params.push(updates.plan); }
  if (updates.settings !== undefined) {
    sets.push('settings = ?');
    params.push(typeof updates.settings === 'string' ? updates.settings : JSON.stringify(updates.settings));
  }
  if (sets.length === 0) return getTeam(id);
  sets.push("updated_at = datetime('now')");
  params.push(id);
  _db.run('UPDATE teams SET ' + sets.join(', ') + ' WHERE id = ?', params);
  return getTeam(id);
}

function deleteTeam(id) {
  _db.run('DELETE FROM teams WHERE id = ?', [id]);
  return { deleted: true };
}

// ── Member Management ──────────────────────────────────────────

function addMember(teamId, userId, options) {
  options = options || {};
  try {
    _db.run(
      `INSERT INTO team_members (team_id, user_id, email, role, invited_by) VALUES (?, ?, ?, ?, ?)`,
      [teamId, userId, options.email || null, options.role || 'member', options.invitedBy || null]
    );
    return { added: true, teamId: teamId, userId: userId, role: options.role || 'member' };
  } catch (e) {
    // UNIQUE constraint — update role instead
    _db.run(
      'UPDATE team_members SET role = ?, email = COALESCE(?, email) WHERE team_id = ? AND user_id = ?',
      [options.role || 'member', options.email || null, teamId, userId]
    );
    return { updated: true, teamId: teamId, userId: userId, role: options.role || 'member' };
  }
}

function removeMember(teamId, userId) {
  _db.run('DELETE FROM team_members WHERE team_id = ? AND user_id = ?', [teamId, userId]);
  return { removed: true };
}

function getMember(teamId, userId) {
  var stmt = _db.prepare('SELECT * FROM team_members WHERE team_id = ? AND user_id = ?');
  stmt.bind([teamId, userId]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  return row;
}

function listMembers(teamId) {
  var stmt = _db.prepare('SELECT * FROM team_members WHERE team_id = ? ORDER BY joined_at ASC');
  stmt.bind([teamId]);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function updateMemberRole(teamId, userId, role) {
  _db.run('UPDATE team_members SET role = ? WHERE team_id = ? AND user_id = ?', [role, teamId, userId]);
  return getMember(teamId, userId);
}

function getTeamForUser(userId) {
  var stmt = _db.prepare('SELECT t.* FROM teams t INNER JOIN team_members tm ON t.id = tm.team_id WHERE tm.user_id = ? ORDER BY tm.joined_at ASC LIMIT 1');
  stmt.bind([userId]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  return row;
}

function isTeamMember(teamId, userId) {
  var member = getMember(teamId, userId);
  return !!member;
}

function hasRole(teamId, userId, minRole) {
  var member = getMember(teamId, userId);
  if (!member) return false;

  var roleHierarchy = { admin: 3, member: 2, viewer: 1 };
  var memberLevel = roleHierarchy[member.role] || 0;
  var requiredLevel = roleHierarchy[minRole] || 0;
  return memberLevel >= requiredLevel;
}

module.exports = {
  init,
  createTeam,
  getTeam,
  getTeamBySlug,
  listTeams,
  updateTeam,
  deleteTeam,
  addMember,
  removeMember,
  getMember,
  listMembers,
  updateMemberRole,
  getTeamForUser,
  isTeamMember,
  hasRole,
};
