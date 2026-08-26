const crypto = require('crypto');
const { getDb, run, get, all } = require('./db.cjs');
const { generateId } = require('./auth.cjs');

function createTeam({ name, ownerId }) {
  getDb();
  const id = generateId();
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') + '-' + id.slice(0, 6);

  run('INSERT INTO teams (id, name, slug, owner_id) VALUES (?, ?, ?, ?)', [id, name.trim(), slug, ownerId]);
  run('INSERT INTO team_members (id, team_id, user_id, role) VALUES (?, ?, ?, ?)', [generateId(), id, ownerId, 'owner']);

  return { id, name: name.trim(), slug, owner_id: ownerId, plan: 'free' };
}

function getTeam(teamId) {
  getDb();
  return get('SELECT * FROM teams WHERE id = ?', [teamId]) || null;
}

function getUserTeams(userId) {
  getDb();
  return all(`
    SELECT t.*, tm.role, tm.joined_at
    FROM teams t JOIN team_members tm ON t.id = tm.team_id
    WHERE tm.user_id = ? AND tm.status = 'active'
    ORDER BY tm.joined_at DESC
  `, [userId]);
}

function getTeamMembers(teamId) {
  getDb();
  return all(`
    SELECT u.id, u.email, u.name, u.avatar_url, tm.role, tm.joined_at, tm.status
    FROM team_members tm JOIN users u ON tm.user_id = u.id
    WHERE tm.team_id = ?
    ORDER BY tm.joined_at ASC
  `, [teamId]);
}

function isTeamMember(teamId, userId) {
  getDb();
  return get('SELECT role FROM team_members WHERE team_id = ? AND user_id = ? AND status = ?', [teamId, userId, 'active']) || null;
}

function addTeamMember(teamId, userId, role = 'member') {
  getDb();
  const existing = get('SELECT id FROM team_members WHERE team_id = ? AND user_id = ?', [teamId, userId]);
  if (existing) {
    run('UPDATE team_members SET status = ?, role = ? WHERE id = ?', ['active', role, existing.id]);
    return;
  }
  run('INSERT INTO team_members (id, team_id, user_id, role) VALUES (?, ?, ?, ?)', [generateId(), teamId, userId, role]);
}

function removeTeamMember(teamId, userId) {
  getDb();
  run('UPDATE team_members SET status = ? WHERE team_id = ? AND user_id = ?', ['removed', teamId, userId]);
}

function updateMemberRole(teamId, userId, role) {
  getDb();
  run('UPDATE team_members SET role = ? WHERE team_id = ? AND user_id = ? AND status = ?', [role, teamId, userId, 'active']);
}

function deleteTeam(teamId) {
  getDb();
  run('DELETE FROM teams WHERE id = ?', [teamId]);
}

function updateTeam(teamId, updates) {
  getDb();
  const fields = [];
  const values = [];
  for (const [key, val] of Object.entries(updates)) {
    if (['name', 'settings'].includes(key) && val !== undefined) {
      fields.push(key + ' = ?');
      values.push(typeof val === 'object' ? JSON.stringify(val) : val);
    }
  }
  if (fields.length === 0) return;
  fields.push('updated_at = datetime("now")');
  values.push(teamId);
  run('UPDATE teams SET ' + fields.join(', ') + ' WHERE id = ?', values);
}

function createInvitation({ teamId, email, role, invitedBy }) {
  getDb();
  const id = generateId();
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

  const existing = get('SELECT id FROM invitations WHERE team_id = ? AND email = ? AND status = ?', [teamId, email, 'pending']);
  if (existing) {
    run('UPDATE invitations SET token = ?, expires_at = ?, role = ? WHERE id = ?', [token, expiresAt, role, existing.id]);
    return { id: existing.id, token, expiresAt };
  }

  run(
    'INSERT INTO invitations (id, team_id, email, role, invited_by, token, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [id, teamId, email.toLowerCase().trim(), role, invitedBy, token, expiresAt]
  );
  return { id, token, expiresAt };
}

function acceptInvitation(token, userId) {
  getDb();
  const inv = get('SELECT * FROM invitations WHERE token = ? AND status = ?', [token, 'pending']);
  if (!inv) throw new Error('Invalid or expired invitation');
  if (new Date(inv.expires_at) < new Date()) throw new Error('Invitation expired');

  addTeamMember(inv.team_id, userId, inv.role);
  run('UPDATE invitations SET status = ? WHERE id = ?', ['accepted', inv.id]);
  return getTeam(inv.team_id);
}

function getTeamInvitations(teamId) {
  getDb();
  return all('SELECT id, email, role, status, created_at, expires_at FROM invitations WHERE team_id = ? AND status = ?', [teamId, 'pending']);
}

function revokeInvitation(invId) {
  getDb();
  run('UPDATE invitations SET status = ? WHERE id = ?', ['revoked', invId]);
}

function recordScan({ teamId, userId, source, filePath, totalMatches, riskScore, piiTypes, profile, mode, result }) {
  getDb();
  const id = generateId();
  run(
    'INSERT INTO scans (id, team_id, user_id, source, file_path, total_matches, risk_score, pii_types, profile, mode, result) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [id, teamId || null, userId || null, source, filePath || null, totalMatches || 0, riskScore || 0, JSON.stringify(piiTypes || []), profile || 'none', mode || 'placeholder', result || null]
  );
  return id;
}

function getTeamScans(teamId, { limit = 50, offset = 0 } = {}) {
  getDb();
  return all('SELECT * FROM scans WHERE team_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?', [teamId, limit, offset]);
}

function getUserScans(userId, { limit = 50, offset = 0 } = {}) {
  getDb();
  return all('SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?', [userId, limit, offset]);
}

function getTeamStats(teamId) {
  getDb();
  const totalScans = get('SELECT COUNT(*) as count FROM scans WHERE team_id = ?', [teamId]);
  const totalMatches = get('SELECT COALESCE(SUM(total_matches), 0) as total FROM scans WHERE team_id = ?', [teamId]);
  const memberCount = get('SELECT COUNT(*) as count FROM team_members WHERE team_id = ? AND status = ?', [teamId, 'active']);
  const recentScans = all('SELECT DATE(created_at) as date, COUNT(*) as scans, SUM(total_matches) as matches FROM scans WHERE team_id = ? GROUP BY DATE(created_at) ORDER BY date DESC LIMIT 30', [teamId]);
  const topPiiTypes = all('SELECT pii_types FROM scans WHERE team_id = ? AND pii_types != ?', [teamId, '[]']);

  const typeCounts = {};
  for (const row of topPiiTypes) {
    try {
      const types = JSON.parse(row.pii_types);
      for (const t of types) typeCounts[t] = (typeCounts[t] || 0) + 1;
    } catch (e) {}
  }
  const topTypes = Object.entries(typeCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);

  return {
    totalScans: totalScans.count, totalMatches: totalMatches.total,
    memberCount: memberCount.count, recentScans,
    topPiiTypes: topTypes.map(([type, count]) => ({ type, count }))
  };
}

function createApiKey({ teamId, userId, name, scopes }) {
  getDb();
  const id = generateId();
  const rawKey = 'afw_' + crypto.randomBytes(24).toString('hex');
  const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
  const keyPrefix = rawKey.slice(0, 12);

  run(
    'INSERT INTO api_keys (id, team_id, user_id, name, key_hash, key_prefix, scopes) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [id, teamId || null, userId, name, keyHash, keyPrefix, JSON.stringify(scopes || ['scan'])]
  );
  return { id, key: rawKey, keyPrefix, name, scopes: scopes || ['scan'] };
}

function validateApiKey(rawKey) {
  getDb();
  const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
  const key = get('SELECT * FROM api_keys WHERE key_hash = ?', [keyHash]);
  if (!key) return null;
  run('UPDATE api_keys SET last_used_at = datetime("now") WHERE id = ?', [key.id]);
  return key;
}

function listApiKeys(teamId) {
  getDb();
  return all('SELECT id, name, key_prefix, scopes, last_used_at, created_at FROM api_keys WHERE team_id = ?', [teamId]);
}

function revokeApiKey(keyId) {
  getDb();
  run('DELETE FROM api_keys WHERE id = ?', [keyId]);
}

module.exports = {
  createTeam, getTeam, getUserTeams, getTeamMembers,
  isTeamMember, addTeamMember, removeTeamMember, updateMemberRole,
  deleteTeam, updateTeam,
  createInvitation, acceptInvitation, getTeamInvitations, revokeInvitation,
  recordScan, getTeamScans, getUserScans, getTeamStats,
  createApiKey, validateApiKey, listApiKeys, revokeApiKey
};
