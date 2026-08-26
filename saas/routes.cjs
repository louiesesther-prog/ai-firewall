const express = require('express');
const auth = require('./auth.cjs');
const teams = require('./teams.cjs');
const { scrub, computeRiskScore } = require('../cli.js');

const router = express.Router();

// ── Auth Routes ──────────────────────────────────────────────
router.post('/auth/register', (req, res) => {
  try {
    const { email, name, password, teamName } = req.body || {};
    if (!email || !name || !password) {
      return res.status(400).json({ error: 'Email, name, and password are required.' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email address.' });
    }

    const user = auth.createUser({ email, name, password });
    const token = auth.generateToken(user);

    let team = null;
    if (teamName) {
      team = teams.createTeam({ name: teamName, ownerId: user.id });
    }

    res.status(201).json({ user, token, team });
  } catch (e) {
    if (e.message === 'Email already registered') {
      return res.status(409).json({ error: e.message });
    }
    console.error('[/auth/register] Error:', e.message);
    res.status(500).json({ error: 'Registration failed.' });
  }
});

router.post('/auth/login', (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }
    const user = auth.authenticateUser({ email, password });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }
    const token = auth.generateToken(user);
    const userTeams = teams.getUserTeams(user.id);
    res.json({ user, token, teams: userTeams });
  } catch (e) {
    console.error('[/auth/login] Error:', e.message);
    res.status(500).json({ error: 'Login failed.' });
  }
});

router.get('/auth/me', auth.authMiddleware, (req, res) => {
  const user = auth.getUserById(req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  const userTeams = teams.getUserTeams(user.id);
  res.json({ user, teams: userTeams });
});

router.put('/auth/profile', auth.authMiddleware, (req, res) => {
  try {
    const { name, avatar_url } = req.body || {};
    auth.updateUser(req.user.sub, { name, avatar_url });
    const user = auth.getUserById(req.user.sub);
    res.json({ user });
  } catch (e) {
    res.status(500).json({ error: 'Update failed.' });
  }
});

router.put('/auth/password', auth.authMiddleware, (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password are required.' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters.' });
    }
    auth.changePassword(req.user.sub, currentPassword, newPassword);
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ── Team Routes ──────────────────────────────────────────────
router.post('/teams', auth.authMiddleware, (req, res) => {
  try {
    const { name } = req.body || {};
    if (!name) return res.status(400).json({ error: 'Team name is required.' });
    const team = teams.createTeam({ name, ownerId: req.user.sub });
    res.status(201).json({ team });
  } catch (e) {
    res.status(500).json({ error: 'Failed to create team.' });
  }
});

router.get('/teams', auth.authMiddleware, (req, res) => {
  const userTeams = teams.getUserTeams(req.user.sub);
  res.json({ teams: userTeams });
});

router.get('/teams/:teamId', auth.authMiddleware, (req, res) => {
  const member = teams.isTeamMember(req.params.teamId, req.user.sub);
  if (!member) return res.status(403).json({ error: 'Not a team member.' });
  const team = teams.getTeam(req.params.teamId);
  if (!team) return res.status(404).json({ error: 'Team not found.' });
  res.json({ team, role: member.role });
});

router.put('/teams/:teamId', auth.authMiddleware, (req, res) => {
  const member = teams.isTeamMember(req.params.teamId, req.user.sub);
  if (!member || !['owner', 'admin'].includes(member.role)) {
    return res.status(403).json({ error: 'Admin or owner role required.' });
  }
  teams.updateTeam(req.params.teamId, req.body);
  const team = teams.getTeam(req.params.teamId);
  res.json({ team });
});

router.delete('/teams/:teamId', auth.authMiddleware, (req, res) => {
  const member = teams.isTeamMember(req.params.teamId, req.user.sub);
  if (!member || member.role !== 'owner') {
    return res.status(403).json({ error: 'Only the team owner can delete the team.' });
  }
  teams.deleteTeam(req.params.teamId);
  res.json({ success: true });
});

// ── Team Members ─────────────────────────────────────────────
router.get('/teams/:teamId/members', auth.authMiddleware, (req, res) => {
  const member = teams.isTeamMember(req.params.teamId, req.user.sub);
  if (!member) return res.status(403).json({ error: 'Not a team member.' });
  const members = teams.getTeamMembers(req.params.teamId);
  res.json({ members });
});

router.put('/teams/:teamId/members/:userId/role', auth.authMiddleware, (req, res) => {
  const member = teams.isTeamMember(req.params.teamId, req.user.sub);
  if (!member || !['owner', 'admin'].includes(member.role)) {
    return res.status(403).json({ error: 'Admin or owner role required.' });
  }
  const { role } = req.body || {};
  if (!['admin', 'member', 'viewer'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role. Use: admin, member, viewer.' });
  }
  teams.updateMemberRole(req.params.teamId, req.params.userId, role);
  res.json({ success: true });
});

router.delete('/teams/:teamId/members/:userId', auth.authMiddleware, (req, res) => {
  const member = teams.isTeamMember(req.params.teamId, req.user.sub);
  if (!member || !['owner', 'admin'].includes(member.role)) {
    return res.status(403).json({ error: 'Admin or owner role required.' });
  }
  if (req.params.userId === req.user.sub) {
    return res.status(400).json({ error: 'Cannot remove yourself. Transfer ownership first.' });
  }
  teams.removeTeamMember(req.params.teamId, req.params.userId);
  res.json({ success: true });
});

// ── Invitations ──────────────────────────────────────────────
router.post('/teams/:teamId/invitations', auth.authMiddleware, (req, res) => {
  const member = teams.isTeamMember(req.params.teamId, req.user.sub);
  if (!member || !['owner', 'admin'].includes(member.role)) {
    return res.status(403).json({ error: 'Admin or owner role required.' });
  }
  const { email, role } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email is required.' });
  const inv = teams.createInvitation({ teamId: req.params.teamId, email, role, invitedBy: req.user.sub });
  res.status(201).json({ invitation: { id: inv.id, email, role, expiresAt: inv.expiresAt } });
});

router.get('/teams/:teamId/invitations', auth.authMiddleware, (req, res) => {
  const member = teams.isTeamMember(req.params.teamId, req.user.sub);
  if (!member) return res.status(403).json({ error: 'Not a team member.' });
  const invitations = teams.getTeamInvitations(req.params.teamId);
  res.json({ invitations });
});

router.post('/invitations/accept', auth.authMiddleware, (req, res) => {
  try {
    const { token } = req.body || {};
    if (!token) return res.status(400).json({ error: 'Invitation token is required.' });
    const team = teams.acceptInvitation(token, req.user.sub);
    res.json({ team });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

router.delete('/teams/:teamId/invitations/:invId', auth.authMiddleware, (req, res) => {
  const member = teams.isTeamMember(req.params.teamId, req.user.sub);
  if (!member || !['owner', 'admin'].includes(member.role)) {
    return res.status(403).json({ error: 'Admin or owner role required.' });
  }
  teams.revokeInvitation(req.params.invId);
  res.json({ success: true });
});

// ── Scans ────────────────────────────────────────────────────
router.post('/scan', auth.authMiddleware, (req, res) => {
  try {
    const { text, mode, profile, teamId } = req.body || {};
    if (!text) return res.status(400).json({ error: 'Text is required.' });

    const result = scrub(text, { mode: mode || 'placeholder' });
    const riskScore = computeRiskScore(result.matches);

    const scanId = teams.recordScan({
      teamId: teamId || null,
      userId: req.user.sub,
      source: 'api',
      totalMatches: result.matches.length,
      riskScore,
      piiTypes: [...new Set(result.matches.map(m => m.type))],
      profile: profile || 'none',
      mode: mode || 'placeholder'
    });

    res.json({ scanId, ...result, riskScore });
  } catch (e) {
    console.error('[/scan] Error:', e.message);
    res.status(500).json({ error: 'Scan failed.' });
  }
});

router.get('/scans', auth.authMiddleware, (req, res) => {
  const { teamId, limit, offset } = req.query;
  const opts = { limit: parseInt(limit) || 50, offset: parseInt(offset) || 0 };

  if (teamId) {
    const member = teams.isTeamMember(teamId, req.user.sub);
    if (!member) return res.status(403).json({ error: 'Not a team member.' });
    const scans = teams.getTeamScans(teamId, opts);
    return res.json({ scans });
  }

  const scans = teams.getUserScans(req.user.sub, opts);
  res.json({ scans });
});

router.get('/teams/:teamId/stats', auth.authMiddleware, (req, res) => {
  const member = teams.isTeamMember(req.params.teamId, req.user.sub);
  if (!member) return res.status(403).json({ error: 'Not a team member.' });
  const stats = teams.getTeamStats(req.params.teamId);
  res.json({ stats });
});

// ── API Keys ─────────────────────────────────────────────────
router.post('/teams/:teamId/api-keys', auth.authMiddleware, (req, res) => {
  const member = teams.isTeamMember(req.params.teamId, req.user.sub);
  if (!member || !['owner', 'admin'].includes(member.role)) {
    return res.status(403).json({ error: 'Admin or owner role required.' });
  }
  const { name, scopes } = req.body || {};
  if (!name) return res.status(400).json({ error: 'Key name is required.' });
  const key = teams.createApiKey({ teamId: req.params.teamId, userId: req.user.sub, name, scopes });
  res.status(201).json({ apiKey: key });
});

router.get('/teams/:teamId/api-keys', auth.authMiddleware, (req, res) => {
  const member = teams.isTeamMember(req.params.teamId, req.user.sub);
  if (!member) return res.status(403).json({ error: 'Not a team member.' });
  const keys = teams.listApiKeys(req.params.teamId);
  res.json({ apiKeys: keys });
});

router.delete('/teams/:teamId/api-keys/:keyId', auth.authMiddleware, (req, res) => {
  const member = teams.isTeamMember(req.params.teamId, req.user.sub);
  if (!member || !['owner', 'admin'].includes(member.role)) {
    return res.status(403).json({ error: 'Admin or owner role required.' });
  }
  teams.revokeApiKey(req.params.keyId);
  res.json({ success: true });
});

module.exports = router;
