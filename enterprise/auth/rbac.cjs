// ── Role-Based Access Control (RBAC) ─────────────────────────────────
// Fine-grained permission model layered on top of team roles. Each role
// maps to a set of permissions; individual members can be granted or
// denied specific permissions (overriding their role). Provides the
// central authorize() check + Express middleware.

var _db = null;

function init(database) {
  _db = database;
}

// ── Permission registry ──────────────────────────────────────────────
// name format: <resource>.<action>
//   resources: api_keys, teams, policies, alerts, audit, reports,
//              webhooks, sso, scim, scheduling, members, marketplace, tenancy
//   actions:   read | write | delete | manage
var DEFAULT_ROLE_PERMISSIONS = {
  owner: ['*'],                                          // everything
  admin: ['*'],                                          // everything
  member: [
    'api_keys.read', 'api_keys.write',
    'policies.read',
    'alerts.read', 'alerts.write',
    'reports.read',
    'marketplace.read',
  ],
  viewer: [
    'api_keys.read', 'policies.read', 'alerts.read', 'reports.read',
    'audit.read', 'marketplace.read',
  ],
};

function registerPermission(permission) {
  var name = permission.name;
  if (!name || name.indexOf('.') === -1) name = permission.resource + '.' + permission.action;
  try {
    _db.run(
      'INSERT OR IGNORE INTO permissions (id, name, resource, action, description) VALUES (?, ?, ?, ?, ?)',
      ['perm_' + require('crypto').randomBytes(6).toString('hex'), name,
       permission.resource || name.split('.')[0],
       permission.action || name.split('.')[1] || 'read',
       permission.description || null]
    );
  } catch (e) { /* already exists / no db */ }
  return {
    id: name, name: name,
    resource: permission.resource || name.split('.')[0],
    action: permission.action || name.split('.')[1] || 'read',
  };
}

// Ensure default role→permission mappings exist in DB
function ensureSeedPermissions() {
  if (!_db) return;
  var all = ['api_keys.read','api_keys.write','api_keys.delete','api_keys.manage',
             'teams.read','teams.write','teams.delete','teams.manage',
             'policies.read','policies.write','policies.delete','policies.manage',
             'alerts.read','alerts.write','alerts.delete',
             'audit.read','audit.manage',
             'reports.read','reports.write',
             'webhooks.read','webhooks.write','webhooks.delete',
             'sso.read','sso.write','sso.manage',
             'scim.read','scim.write','scim.delete',
             'scheduling.read','scheduling.write',
             'members.read','members.write','members.manage',
             'marketplace.read','marketplace.write',
             'tenancy.read','tenancy.write','tenancy.manage'];
  var resources = {
    'api_keys': ['read','write','delete','manage'], 'teams': ['read','write','delete','manage'],
    'policies': ['read','write','delete','manage'], 'alerts': ['read','write','delete'],
    'audit': ['read','manage'], 'reports': ['read','write'],
    'webhooks': ['read','write','delete'], 'sso': ['read','write','manage'],
    'scim': ['read','write','delete'], 'scheduling': ['read','write'],
    'members': ['read','write','manage'], 'marketplace': ['read','write'],
    'tenancy': ['read','write','manage'],
  };
  for (var res in resources) {
    for (var i = 0; i < resources[res].length; i++) {
      registerPermission({ resource: res, action: resources[res][i] });
    }
  }
  // Role mappings
  for (var role in DEFAULT_ROLE_PERMISSIONS) {
    var perms = DEFAULT_ROLE_PERMISSIONS[role];
    for (var p = 0; p < perms.length; p++) {
      _db.run('INSERT OR IGNORE INTO role_permissions (role, permission_id) VALUES (?, ?)', [role, perms[p]]);
    }
  }
  void all;
}

// ── Permission lookup ────────────────────────────────────────────────

// Does a role's permission set contain `permission`?
function _permMatch(permSet, permission) {
  if (!permSet) return false;
  if (permSet.indexOf('*') !== -1) return true;
  // exact match or wildcard on resource/action segments
  for (var i = 0; i < permSet.length; i++) {
    var p = permSet[i];
    if (p === permission) return true;
    if (p === '*') return true;
    if (p.indexOf('.*') !== -1) {
      var base = p.substring(0, p.length - 1); // e.g. "api_keys."
      if (permission.indexOf(base) === 0) return true;
    }
  }
  return false;
}

// Get the resolved permission set for a user within a team, combining
// base role permissions + individual grants/denials.
function getPermissions(teamId, userId) {
  if (!_db) return { permissions: [], effective: false };

  // Find user's role in team
  var role = null;
  var memberStmt = _db.prepare('SELECT role FROM team_members WHERE team_id = ? AND user_id = ?');
  memberStmt.bind([teamId, userId]);
  if (memberStmt.step()) role = memberStmt.getAsObject().role;
  memberStmt.free();

  var baseSet;
  if (!role) {
    baseSet = [];
  } else if (role === 'admin' || role === 'owner') {
    baseSet = ['*'];
  } else {
    baseSet = loadRolePermissions(role);
  }

  // Apply per-member grants/denials
  var overrides = loadMemberPermissions(teamId, userId);
  for (var i = 0; i < overrides.length; i++) {
    var ov = overrides[i];
    if (ov.granted && ov.granted !== '0' && ov.granted !== 0) {
      if (baseSet.indexOf(ov.name) === -1 && ov.name !== '*') baseSet.push(ov.name);
    } else {
      // denial: remove permission
      baseSet = baseSet.filter(function(p) { return p !== ov.name && !(ov.name === '*' ? true : false); });
      // remove resource wildcards too for resource-level deny
      if (ov.name && ov.name.indexOf('.*') === -1 && ov.name.indexOf('.') !== -1) {
        var res = ov.name.split('.')[0];
        baseSet = baseSet.filter(function(p) { return p !== (res + '.*') && p !== '*'; });
      }
    }
  }

  return { permissions: baseSet, effective: true, role: role };
}

function loadRolePermissions(role) {
  var stmt = _db.prepare(
    'SELECT p.name FROM role_permissions rp INNER JOIN permissions p ON rp.permission_id = p.id WHERE rp.role = ?'
  );
  stmt.bind([role]);
  var result = [];
  while (stmt.step()) result.push(stmt.getAsObject().name);
  stmt.free();
  return result;
}

function loadMemberPermissions(teamId, userId) {
  var stmt = _db.prepare(
    'SELECT mp.granted, p.name FROM member_permissions mp INNER JOIN permissions p ON mp.permission_id = p.id WHERE mp.team_id = ? AND mp.user_id = ?'
  );
  stmt.bind([teamId, userId]);
  var result = [];
  while (stmt.step()) result.push(stmt.getAsObject());
  stmt.free();
  return result;
}

// Does the user have `permission` (e.g. "api_keys.write") in the team?
function hasPermission(teamId, userId, permission) {
  var resolved = getPermissions(teamId, userId);
  return _permMatch(resolved.permissions, permission);
}

// Convenience: user has ANY of the given permissions
function hasAnyPermission(teamId, userId, permissions) {
  for (var i = 0; i < permissions.length; i++) {
    if (hasPermission(teamId, userId, permissions[i])) return true;
  }
  return false;
}

// Convenience: user has ALL of the given permissions
function hasAllPermissions(teamId, userId, permissions) {
  for (var i = 0; i < permissions.length; i++) {
    if (!hasPermission(teamId, userId, permissions[i])) return false;
  }
  return true;
}

// ── Grant/deny individual permissions ────────────────────────────────

function setMemberPermission(teamId, userId, permission, granted) {
  // Find permission id
  var id = permission;
  var stmt = _db.prepare('SELECT id FROM permissions WHERE name = ?');
  stmt.bind([permission]);
  if (stmt.step()) id = stmt.getAsObject().id;
  stmt.free();

  _db.run(
    'INSERT OR REPLACE INTO member_permissions (team_id, user_id, permission_id, granted) VALUES (?, ?, ?, ?)',
    [teamId, userId, id, granted ? 1 : 0]
  );
  return { teamId: teamId, userId: userId, permission: permission, granted: !!granted };
}

function clearMemberPermission(teamId, userId, permission) {
  var stmt = _db.prepare('SELECT id FROM permissions WHERE name = ?');
  stmt.bind([permission]);
  var id = null;
  if (stmt.step()) id = stmt.getAsObject().id;
  stmt.free();
  if (id) _db.run('DELETE FROM member_permissions WHERE team_id = ? AND user_id = ? AND permission_id = ?', [teamId, userId, id]);
  return { cleared: true };
}

function listMemberPermissions(teamId, userId) {
  var stmt = _db.prepare(
    'SELECT mp.granted as granted, p.name FROM member_permissions mp INNER JOIN permissions p ON mp.permission_id = p.id WHERE mp.team_id = ? AND mp.user_id = ?'
  );
  stmt.bind([teamId, userId]);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// ── Express middleware ───────────────────────────────────────────────
// Reads teamId from x-team-id header and userId from x-user-id header
// (or req.user from SSO). Authorization Bearer token may also provide
// teamId/userId via SSO payload.
//
// Usage: rbac.requirePermission('api_keys.write')
function requirePermission(permission) {
  return function(req, res, next) {
    var ctx = getContext(req);
    if (!ctx.teamId || !ctx.userId) {
      return res.status(401).json({ error: 'Authorization required', required: permission });
    }
    if (!hasPermission(ctx.teamId, ctx.userId, permission)) {
      return res.status(403).json({ error: 'Forbidden: missing permission', required: permission });
    }
    next();
  };
}

function requireAnyPermission(permissions) {
  return function(req, res, next) {
    var ctx = getContext(req);
    if (!ctx.teamId || !ctx.userId) {
      return res.status(401).json({ error: 'Authorization required' });
    }
    if (!hasAnyPermission(ctx.teamId, ctx.userId, permissions)) {
      return res.status(403).json({ error: 'Forbidden: insufficient permissions', required: permissions });
    }
    next();
  };
}

// Resolve team/user identity from request (SSO user or headers)
function getContext(req) {
  var teamId = null;
  var userId = null;

  if (req.user) {
    teamId = req.user.team || null;
    userId = req.user.sub || req.user.userId || null;
  }
  if (!teamId) teamId = req.headers['x-team-id'] || null;
  if (!userId) userId = req.headers['x-user-id'] || null;

  return { teamId: teamId, userId: userId };
}

function middleware() {
  return function(req, res, next) {
    req.rbac = {
      context: getContext(req),
      has: function(perm) { return this.context.teamId && this.context.userId ? hasPermission(this.context.teamId, this.context.userId, perm) : false; },
    };
    next();
  };
}

module.exports = {
  init,
  registerPermission,
  ensureSeedPermissions,
  getPermissions,
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
  setMemberPermission,
  clearMemberPermission,
  listMemberPermissions,
  requirePermission,
  requireAnyPermission,
  getContext,
  middleware,
  DEFAULT_ROLE_PERMISSIONS,
};
