// ── AI Firewall SaaS Dashboard ───────────────────────────────
(function() {
  const API = '/api';
  let token = localStorage.getItem('afw_token');
  let user = null;
  let team = null;

  // ── Auth Guard ────────────────────────────────────────────
  if (!token) { window.location.href = '/login'; return; }

  function headers() {
    return { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token };
  }

  async function api(path, opts = {}) {
    const res = await fetch(API + path, { headers: headers(), ...opts });
    if (res.status === 401) { logout(); throw new Error('Session expired'); }
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Request failed');
    return data;
  }

  // ── Toast ─────────────────────────────────────────────────
  window.showToast = function(msg, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = 'toast toast-' + type;
    toast.textContent = msg;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
  };

  // ── Navigation ────────────────────────────────────────────
  window.showPage = function(page) {
    document.querySelectorAll('.page').forEach(p => p.style.display = 'none');
    document.querySelectorAll('.nav-item[data-page]').forEach(n => n.classList.remove('active'));
    const el = document.getElementById('page-' + page);
    if (el) el.style.display = 'block';
    const nav = document.querySelector('[data-page="' + page + '"]');
    if (nav) nav.classList.add('active');
    if (page === 'history') loadHistory();
    if (page === 'team') loadTeam();
    if (page === 'apikeys') loadApiKeys();
  };

  window.logout = function() {
    localStorage.removeItem('afw_token');
    localStorage.removeItem('afw_user');
    localStorage.removeItem('afw_team');
    window.location.href = '/login';
  };

  // ── Init ──────────────────────────────────────────────────
  async function init() {
    try {
      const data = await api('/auth/me');
      user = data.user;
      team = data.teams && data.teams.length > 0 ? data.teams[0] : null;

      document.getElementById('userName').textContent = user.name;
      document.getElementById('userEmail').textContent = user.email;
      document.getElementById('userAvatar').textContent = user.name.charAt(0).toUpperCase();
      document.getElementById('planBadge').textContent = user.plan.charAt(0).toUpperCase() + user.plan.slice(1);
      document.getElementById('planBadge').className = 'badge badge-' + user.plan;

      document.getElementById('settingsName').value = user.name;
      document.getElementById('settingsEmail').value = user.email;

      if (team) {
        document.getElementById('teamName').textContent = team.name;
        document.getElementById('teamPlan').textContent = team.plan;
      }

      loadOverview();
    } catch (e) {
      console.error('Init failed:', e);
      logout();
    }
  }

  // ── Overview ──────────────────────────────────────────────
  async function loadOverview() {
    try {
      const params = team ? '?teamId=' + team.id : '';
      const scansData = await api('/scans' + params);
      const scans = scansData.scans || [];

      document.getElementById('statScans').textContent = scans.length;
      const totalMatches = scans.reduce((s, sc) => s + (sc.total_matches || 0), 0);
      document.getElementById('statMatches').textContent = totalMatches;
      const avgRisk = scans.length > 0 ? Math.round(scans.reduce((s, sc) => s + (sc.risk_score || 0), 0) / scans.length) : 0;
      document.getElementById('statRisk').textContent = avgRisk;

      if (team) {
        try {
          const stats = await api('/teams/' + team.id + '/stats');
          document.getElementById('statMembers').textContent = stats.stats.memberCount;
        } catch (e) { /* ignore */ }
      }

      const tbody = document.getElementById('recentScansBody');
      if (scans.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-dim);padding:24px">No scans yet. Go to Scan to get started.</td></tr>';
        return;
      }
      tbody.innerHTML = scans.slice(0, 10).map(sc => {
        const date = new Date(sc.created_at).toLocaleDateString();
        return '<tr><td>' + date + '</td><td>' + esc(sc.source) + '</td><td>' + sc.total_matches + '</td><td>' + sc.risk_score + '</td><td>' + esc(sc.profile) + '</td></tr>';
      }).join('');
    } catch (e) {
      console.error('loadOverview:', e);
    }
  }

  // ── Scan ──────────────────────────────────────────────────
  window.handleScan = async function(e) {
    e.preventDefault();
    const btn = document.getElementById('scanBtn');
    const input = document.getElementById('scanInput').value.trim();
    if (!input) return;

    btn.textContent = 'Scanning...';
    btn.disabled = true;

    try {
      const data = await api('/scan', {
        method: 'POST',
        body: JSON.stringify({
          text: input,
          mode: document.getElementById('scanMode').value,
          profile: document.getElementById('scanProfile').value,
          teamId: team ? team.id : undefined
        })
      });

      document.getElementById('resultMatches').textContent = data.matches.length;
      document.getElementById('resultRisk').textContent = data.riskScore;
      document.getElementById('resultScrubbed').value = data.scrubbed;

      const details = document.getElementById('resultDetails');
      if (data.matches.length === 0) {
        details.innerHTML = '<p style="color:var(--success)">No PII detected.</p>';
      } else {
        details.innerHTML = '<table><thead><tr><th>Type</th><th>Confidence</th><th>Original</th><th>Replacement</th></tr></thead><tbody>' +
          data.matches.map(m =>
            '<tr><td><span class="badge badge-admin">' + esc(m.type) + '</span></td><td>' + m.confidence + '</td><td style="font-family:monospace;font-size:12px">' + esc(m.original) + '</td><td style="font-family:monospace;font-size:12px">' + esc(m.replacement) + '</td></tr>'
          ).join('') + '</tbody></table>';
      }
      document.getElementById('scanResult').style.display = 'block';
    } catch (err) {
      showToast(err.message, 'error');
    }
    btn.textContent = 'Scan for PII';
    btn.disabled = false;
  };

  // ── History ───────────────────────────────────────────────
  async function loadHistory() {
    try {
      const params = team ? '?teamId=' + team.id : '';
      const data = await api('/scans' + params);
      const scans = data.scans || [];
      const tbody = document.getElementById('historyBody');
      if (scans.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-dim);padding:24px">No scan history yet.</td></tr>';
        return;
      }
      tbody.innerHTML = scans.map(sc => {
        const date = new Date(sc.created_at).toLocaleDateString();
        return '<tr><td>' + date + '</td><td>' + esc(sc.source) + '</td><td>' + esc(sc.file_path || '—') + '</td><td>' + sc.total_matches + '</td><td>' + sc.risk_score + '</td><td>' + esc(sc.mode) + '</td></tr>';
      }).join('');
    } catch (e) {
      console.error('loadHistory:', e);
    }
  }

  // ── Team ──────────────────────────────────────────────────
  async function loadTeam() {
    if (!team) {
      document.getElementById('noTeamMsg').style.display = 'block';
      document.getElementById('teamContent').style.display = 'none';
      return;
    }
    document.getElementById('noTeamMsg').style.display = 'none';
    document.getElementById('teamContent').style.display = 'block';

    try {
      const data = await api('/teams/' + team.id + '/members');
      const members = data.members || [];
      document.getElementById('teamMemberCount').textContent = members.length;
      const tbody = document.getElementById('membersBody');
      tbody.innerHTML = members.map(m => {
        const date = new Date(m.joined_at).toLocaleDateString();
        return '<tr><td>' + esc(m.name) + '</td><td>' + esc(m.email) + '</td><td><span class="badge badge-' + m.role + '">' + m.role + '</span></td><td>' + date + '</td><td></td></tr>';
      }).join('');
    } catch (e) {
      console.error('loadTeam:', e);
    }
  }

  window.showCreateTeamModal = function() {
    document.getElementById('createTeamModal').classList.add('active');
  };

  window.showInviteModal = function() {
    if (!team) { showToast('Create a team first', 'error'); return; }
    document.getElementById('inviteModal').classList.add('active');
  };

  window.handleCreateTeam = async function() {
    const name = document.getElementById('newTeamName').value.trim();
    if (!name) return;
    try {
      const data = await api('/teams', { method: 'POST', body: JSON.stringify({ name }) });
      team = data.team;
      localStorage.setItem('afw_team', JSON.stringify(team));
      document.getElementById('teamName').textContent = team.name;
      closeModal('createTeamModal');
      showToast('Team created!', 'success');
      loadTeam();
    } catch (e) {
      showToast(e.message, 'error');
    }
  };

  window.handleInvite = async function() {
    const email = document.getElementById('inviteEmail').value.trim();
    const role = document.getElementById('inviteRole').value;
    if (!email) return;
    try {
      await api('/teams/' + team.id + '/invitations', {
        method: 'POST',
        body: JSON.stringify({ email, role })
      });
      closeModal('inviteModal');
      showToast('Invitation sent to ' + email, 'success');
    } catch (e) {
      showToast(e.message, 'error');
    }
  };

  // ── API Keys ──────────────────────────────────────────────
  window.showCreateKeyModal = function() {
    if (!team) { showToast('Create a team first', 'error'); return; }
    document.getElementById('createKeyModal').classList.add('active');
  };

  async function loadApiKeys() {
    if (!team) return;
    try {
      const data = await api('/teams/' + team.id + '/api-keys');
      const keys = data.apiKeys || [];
      const tbody = document.getElementById('keysBody');
      if (keys.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-dim);padding:24px">No API keys yet.</td></tr>';
        return;
      }
      tbody.innerHTML = keys.map(k => {
        const lastUsed = k.last_used_at ? new Date(k.last_used_at).toLocaleDateString() : 'Never';
        return '<tr><td>' + esc(k.name) + '</td><td><code>' + esc(k.key_prefix) + '...</code></td><td>' + esc(k.scopes) + '</td><td>' + lastUsed + '</td><td><button class="btn btn-danger btn-sm" onclick="revokeKey(\'' + k.id + '\')">Revoke</button></td></tr>';
      }).join('');
    } catch (e) {
      console.error('loadApiKeys:', e);
    }
  }

  window.handleCreateKey = async function() {
    const name = document.getElementById('newKeyName').value.trim();
    if (!name) return;
    try {
      const data = await api('/teams/' + team.id + '/api-keys', {
        method: 'POST',
        body: JSON.stringify({ name })
      });
      closeModal('createKeyModal');
      showToast('API Key: ' + data.apiKey.key + ' — Copy it now, it won\'t be shown again!', 'success');
      loadApiKeys();
    } catch (e) {
      showToast(e.message, 'error');
    }
  };

  window.revokeKey = async function(keyId) {
    if (!confirm('Revoke this API key?')) return;
    try {
      await api('/teams/' + team.id + '/api-keys/' + keyId, { method: 'DELETE' });
      showToast('API key revoked', 'success');
      loadApiKeys();
    } catch (e) {
      showToast(e.message, 'error');
    }
  };

  // ── Settings ──────────────────────────────────────────────
  window.handleUpdateProfile = async function(e) {
    e.preventDefault();
    try {
      const name = document.getElementById('settingsName').value.trim();
      await api('/auth/profile', { method: 'PUT', body: JSON.stringify({ name }) });
      user.name = name;
      localStorage.setItem('afw_user', JSON.stringify(user));
      document.getElementById('userName').textContent = name;
      document.getElementById('userAvatar').textContent = name.charAt(0).toUpperCase();
      showToast('Profile updated', 'success');
    } catch (e) {
      showToast(e.message, 'error');
    }
  };

  window.handleChangePassword = async function(e) {
    e.preventDefault();
    try {
      await api('/auth/password', {
        method: 'PUT',
        body: JSON.stringify({
          currentPassword: document.getElementById('currentPassword').value,
          newPassword: document.getElementById('newPassword').value
        })
      });
      document.getElementById('currentPassword').value = '';
      document.getElementById('newPassword').value = '';
      showToast('Password updated', 'success');
    } catch (e) {
      showToast(e.message, 'error');
    }
  };

  // ── Helpers ───────────────────────────────────────────────
  function esc(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  window.closeModal = function(id) {
    document.getElementById(id).classList.remove('active');
  };

  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) overlay.classList.remove('active');
    });
  });

  // ── Boot ──────────────────────────────────────────────────
  init();
})();
