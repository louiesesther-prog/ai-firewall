// ── SCIM 2.0 (System for Cross-domain Identity Management) ─────────
// Minimal self-contained SCIM provisioning: users and groups with the
// core SCIM resource attributes, plus listing/update/delete (patch by
// replacement). No external IdP required.

const crypto = require('crypto');

var _db = null;

function init(database) {
  _db = database;
}

function _newId(prefix) {
  return prefix + Date.now().toString(36) + '_' + crypto.randomBytes(4).toString('hex');
}

function _userToScim(row, meta) {
  var attributes = {};
  try { attributes = JSON.parse(row.attributes || '{}'); } catch (e) {}
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    id: row.id,
    externalId: row.external_id,
    userName: row.user_name,
    displayName: row.display_name,
    name: { givenName: row.given_name, familyName: row.family_name },
    emails: [{ value: row.email, primary: true }],
    active: !!row.active,
    meta: meta,
  };
}

// ── Users ───────────────────────────────────────────────────────────

function createUser(teamId, body) {
  body = body || {};
  var id = _newId('su_');
  var externalId = body.externalId || body.userName || id;
  var name = body.name || {};

  _db.run(
    `INSERT INTO scim_users (id, external_id, user_name, display_name, email, given_name, family_name, active, team_id, attributes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      id,
      externalId,
      body.userName || null,
      body.displayName || null,
      (body.emails && body.emails[0] && body.emails[0].value) || body.email || null,
      name.givenName || null,
      name.familyName || null,
      body.active !== false ? 1 : 0,
      teamId,
      typeof body.attributes === 'string' ? body.attributes : JSON.stringify(body.attributes || {}),
    ]
  );

  return getUser(id);
}

function getUser(id) {
  var stmt = _db.prepare("SELECT * FROM scim_users WHERE id = ? AND deleted_at IS NULL");
  stmt.bind([id]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  if (!row) return null;
  return _userToScim(row, { resourceType: 'User', created: row.created_at, lastModified: row.updated_at });
}

function findUserByExternalId(externalId) {
  var stmt = _db.prepare("SELECT * FROM scim_users WHERE external_id = ? AND deleted_at IS NULL");
  stmt.bind([externalId]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  if (!row) return null;
  return _userToScim(row, { resourceType: 'User', created: row.created_at, lastModified: row.updated_at });
}

function listUsers(teamId, options) {
  options = options || {};
  var where = ['deleted_at IS NULL'];
  var params = [];
  if (teamId) { where.push('team_id = ?'); params.push(teamId); }

  var sql = 'SELECT * FROM scim_users WHERE ' + where.join(' AND ') + ' ORDER BY created_at ASC';
  var limit = parseInt(options.count, 10) || 100;
  var startIndex = parseInt(options.startIndex, 10) || 1;
  var totalStmt = _db.prepare('SELECT COUNT(*) as c FROM scim_users WHERE ' + where.join(' AND '));
  totalStmt.bind(params.slice());
  var total = 0;
  if (totalStmt.step()) total = totalStmt.getAsObject().c;
  totalStmt.free();

  sql += ' LIMIT ? OFFSET ?';
  var stmt = _db.prepare(sql);
  stmt.bind(params.concat([limit, (startIndex - 1)]));
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();

  return {
    schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
    totalResults: total,
    itemsPerPage: limit,
    startIndex: startIndex,
    Resources: rows.map(r => _userToScim(r, { resourceType: 'User', created: r.created_at, lastModified: r.updated_at })),
  };
}

function updateUser(id, body, partial) {
  var existing = getUser(id);
  if (!existing) return null;

  var sets = [];
  var params = [];
  var name = body.name || {};

  if (body.userName !== undefined) { sets.push('user_name = ?'); params.push(body.userName); }
  if (body.displayName !== undefined) { sets.push('display_name = ?'); params.push(body.displayName); }
  if (body.active !== undefined) { sets.push('active = ?'); params.push(body.active ? 1 : 0); }
  if (name.givenName !== undefined) { sets.push('given_name = ?'); params.push(name.givenName); }
  if (name.familyName !== undefined) { sets.push('family_name = ?'); params.push(name.familyName); }
  if (body.emails && body.emails[0] && body.emails[0].value !== undefined) { sets.push('email = ?'); params.push(body.emails[0].value); }
  if (body.externalId !== undefined) { sets.push('external_id = ?'); params.push(body.externalId); }
  if (body.attributes !== undefined) {
    sets.push('attributes = ?');
    params.push(typeof body.attributes === 'string' ? body.attributes : JSON.stringify(body.attributes));
  }
  if (!partial && body.attributes === undefined && Object.keys(body).length > 0) {
    // Full replacement retains optional attrs; keep minimal
  }

  if (sets.length === 0) return existing;
  sets.push("updated_at = datetime('now')");
  params.push(id);
  _db.run('UPDATE scim_users SET ' + sets.join(', ') + ' WHERE id = ?', params);
  return getUser(id);
}

function deleteUser(id) {
  _db.run("UPDATE scim_users SET deleted_at = datetime('now'), active = 0, updated_at = datetime('now') WHERE id = ?", [id]);
  return { deleted: true };
}

// ── Groups ──────────────────────────────────────────────────────────

function createGroup(teamId, body) {
  body = body || {};
  var id = _newId('sg_');
  var externalId = body.externalId || body.displayName || id;

  _db.run(
    `INSERT INTO scim_groups (id, display_name, external_id, team_id) VALUES (?, ?, ?, ?)`,
    [id, body.displayName || body.name || null, externalId, teamId]
  );

  var group = getGroup(id);
  // Add members
  if (body.members && group) {
    setGroupMembers(id, body.members.map(m => m.value));
  }
  return getGroup(id);
}

function getGroup(id) {
  var stmt = _db.prepare('SELECT * FROM scim_groups WHERE id = ?');
  stmt.bind([id]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  if (!row) return null;

  var memStmt = _db.prepare('SELECT user_id FROM scim_group_members WHERE group_id = ?');
  memStmt.bind([id]);
  var members = [];
  while (memStmt.step()) members.push({ value: memStmt.getAsObject().user_id });
  memStmt.free();

  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
    id: row.id,
    externalId: row.external_id,
    displayName: row.display_name,
    members: members,
    meta: { resourceType: 'Group', created: row.created_at, lastModified: row.updated_at },
  };
}

function listGroups(teamId, options) {
  options = options || {};
  var where = [];
  var params = [];
  if (teamId) { where.push('team_id = ?'); params.push(teamId); }
  var sql = 'SELECT * FROM scim_groups';
  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  if (!options.includeEmpty && false) {}
  if (options.filter) {}
  sql += ' ORDER BY created_at ASC';
  var stmt = _db.prepare(sql);
  if (params.length) stmt.bind(params);
  var rows = [];
  while (stmt.step()) rows.push({ id: stmt.getAsObject().id });
  stmt.free();
  var groups = rows.map(r => getGroup(r.id));
  return {
    schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
    totalResults: groups.length,
    Resources: groups,
  };
}

function setGroupMembers(groupId, userIds) {
  _db.run('DELETE FROM scim_group_members WHERE group_id = ?', [groupId]);
  for (var i = 0; i < userIds.length; i++) {
    _db.run('INSERT OR IGNORE INTO scim_group_members (group_id, user_id) VALUES (?, ?)', [groupId, userIds[i]]);
  }
  _db.run("UPDATE scim_groups SET updated_at = datetime('now') WHERE id = ?", [groupId]);
  return getGroup(groupId);
}

function updateGroup(id, body, partial) {
  if (!partial && body.members) {
    setGroupMembers(id, (body.members || []).map(m => m.value));
    return getGroup(id);
  }
  var sets = [];
  var params = [];
  if (body.displayName !== undefined) { sets.push('display_name = ?'); params.push(body.displayName); }
  if (body.externalId !== undefined) { sets.push('external_id = ?'); params.push(body.externalId); }
  if (body.members !== undefined) {
    setGroupMembers(id, (body.members || []).map(m => m.value));
  }
  if (sets.length > 0) {
    sets.push("updated_at = datetime('now')");
    params.push(id);
    _db.run('UPDATE scim_groups SET ' + sets.join(', ') + ' WHERE id = ?', params);
  }
  return getGroup(id);
}

function deleteGroup(id) {
  _db.run('DELETE FROM scim_group_members WHERE group_id = ?', [id]);
  _db.run('DELETE FROM scim_groups WHERE id = ?', [id]);
  return { deleted: true };
}

module.exports = {
  init,
  createUser,
  getUser,
  findUserByExternalId,
  listUsers,
  updateUser,
  deleteUser,
  createGroup,
  getGroup,
  listGroups,
  setGroupMembers,
  updateGroup,
  deleteGroup,
};
