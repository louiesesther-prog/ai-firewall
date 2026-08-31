// ── Scheduled Compliance Reports ──────────────────────────────────
// Recurring report generation with cron-like scheduling, delivery
// via webhook or email, and execution history.

const crypto = require('crypto');

var _db = null;
var _complianceExport = null;
var _webhookDispatcher = null;
var _timers = new Map();

function init(database, complianceExport, webhookDispatcher) {
  _db = database;
  _complianceExport = complianceExport;
  _webhookDispatcher = webhookDispatcher;
}

function createSchedule(options) {
  options = options || {};
  var id = 'sr_' + Date.now().toString(36) + '_' + crypto.randomBytes(4).toString('hex');

  var nextRun = calculateNextRun(options.schedule || '0 0 1 * *');

  _db.run(
    `INSERT INTO scheduled_reports (id, team_id, name, report_type, schedule, recipients, delivery_method, next_run_at, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      id,
      options.teamId,
      options.name || options.reportType + ' report',
      options.reportType || 'soc2',
      options.schedule || '0 0 1 * *',
      typeof options.recipients === 'string' ? options.recipients : JSON.stringify(options.recipients || []),
      options.deliveryMethod || 'webhook',
      nextRun,
      options.createdBy || null,
    ]
  );

  scheduleTimer(id, nextRun);

  return {
    id: id,
    teamId: options.teamId,
    name: options.name || options.reportType + ' report',
    reportType: options.reportType || 'soc2',
    schedule: options.schedule || '0 0 1 * *',
    nextRunAt: nextRun,
  };
}

function listSchedules(teamId, options) {
  options = options || {};
  var where = [];
  var params = [];
  if (teamId) { where.push('team_id = ?'); params.push(teamId); }
  if (!options.includeDisabled) { where.push('enabled = 1'); }

  var sql = 'SELECT * FROM scheduled_reports';
  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  sql += ' ORDER BY created_at DESC';

  var stmt = _db.prepare(sql);
  if (params.length) stmt.bind(params);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function getSchedule(id) {
  var stmt = _db.prepare('SELECT * FROM scheduled_reports WHERE id = ?');
  stmt.bind([id]);
  var row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  return row;
}

function updateSchedule(id, updates) {
  var sets = [];
  var params = [];
  if (updates.name !== undefined) { sets.push('name = ?'); params.push(updates.name); }
  if (updates.schedule !== undefined) { sets.push('schedule = ?'); params.push(updates.schedule); }
  if (updates.recipients !== undefined) {
    sets.push('recipients = ?');
    params.push(typeof updates.recipients === 'string' ? updates.recipients : JSON.stringify(updates.recipients));
  }
  if (updates.deliveryMethod !== undefined) { sets.push('delivery_method = ?'); params.push(updates.deliveryMethod); }
  if (updates.enabled !== undefined) { sets.push('enabled = ?'); params.push(updates.enabled ? 1 : 0); }

  if (sets.length === 0) return getSchedule(id);
  params.push(id);
  _db.run('UPDATE scheduled_reports SET ' + sets.join(', ') + ' WHERE id = ?', params);

  // Reschedule timer if schedule changed
  if (updates.schedule !== undefined) {
    cancelTimer(id);
    var schedule = getSchedule(id);
    if (schedule && schedule.enabled) {
      var nextRun = calculateNextRun(schedule.schedule);
      _db.run("UPDATE scheduled_reports SET next_run_at = ? WHERE id = ?", [nextRun, id]);
      scheduleTimer(id, nextRun);
    }
  }

  return getSchedule(id);
}

function deleteSchedule(id) {
  cancelTimer(id);
  _db.run('DELETE FROM scheduled_reports WHERE id = ?', [id]);
  return { deleted: true };
}

function runSchedule(id) {
  var schedule = getSchedule(id);
  if (!schedule) return { error: 'Schedule not found' };

  // Record execution
  _db.run(
    `INSERT INTO scheduled_report_history (schedule_id, status) VALUES (?, 'running')`,
    [id]
  );

  var historyStmt = _db.prepare('SELECT last_insert_rowid() as id');
  var historyId = null;
  if (historyStmt.step()) historyId = historyStmt.getAsObject().id;
  historyStmt.free();

  try {
    // Calculate period from schedule
    var now = new Date();
    var periodStart, periodEnd;

    if (schedule.report_type === 'gdpr_art30') {
      periodStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().split('T')[0];
      periodEnd = now.toISOString().split('T')[0];
    } else {
      periodStart = new Date(now.getFullYear(), now.getMonth() - 1, 1).toISOString().split('T')[0];
      periodEnd = new Date(now.getFullYear(), now.getMonth(), 0).toISOString().split('T')[0];
    }

    var report = null;
    if (_complianceExport) {
      report = _complianceExport.generateReport({
        reportType: schedule.report_type,
        teamId: schedule.team_id,
        periodStart: periodStart,
        periodEnd: periodEnd,
        generatedBy: 'scheduled:' + id,
      });
    }

    // Update history
    _db.run(
      `UPDATE scheduled_report_history SET status = 'completed', completed_at = datetime('now'), report_id = ? WHERE id = ?`,
      [report ? report.id : null, historyId]
    );

    // Update schedule
    var nextRun = calculateNextRun(schedule.schedule);
    _db.run(
      "UPDATE scheduled_reports SET last_run_at = datetime('now'), next_run_at = ? WHERE id = ?",
      [nextRun, id]
    );

    // Deliver report via webhook if configured
    if (_webhookDispatcher && schedule.delivery_method === 'webhook') {
      var recipients;
      try { recipients = JSON.parse(schedule.recipients); } catch (e) { recipients = []; }

      for (var i = 0; i < recipients.length; i++) {
        try {
          _webhookDispatcher.dispatchEvent('compliance_report', {
            scheduleId: id,
            reportType: schedule.report_type,
            report: report,
            recipients: recipients,
          });
        } catch (e) { /* non-blocking */ }
      }
    }

    // Schedule next run
    scheduleTimer(id, nextRun);

    return { success: true, report: report, nextRunAt: nextRun };
  } catch (e) {
    _db.run(
      `UPDATE scheduled_report_history SET status = 'failed', error_message = ?, completed_at = datetime('now') WHERE id = ?`,
      [e.message, historyId]
    );
    return { error: e.message };
  }
}

function getHistory(scheduleId, options) {
  options = options || {};
  var stmt = _db.prepare('SELECT * FROM scheduled_report_history WHERE schedule_id = ? ORDER BY started_at DESC LIMIT ?');
  stmt.bind([scheduleId, options.limit || 10]);
  var rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// ── Timer Management ─────────────────────────────────────────────

function scheduleTimer(scheduleId, nextRunAt) {
  if (!nextRunAt) return;
  var delay = new Date(nextRunAt).getTime() - Date.now();
  if (delay <= 0) {
    // Run immediately if overdue
    runSchedule(scheduleId);
    return;
  }

  var timer = setTimeout(function() {
    runSchedule(scheduleId);
    _timers.delete(scheduleId);
  }, Math.min(delay, 2147483647)); // Cap at ~24 days for setTimeout

  _timers.set(scheduleId, timer);
}

function cancelTimer(scheduleId) {
  if (_timers.has(scheduleId)) {
    clearTimeout(_timers.get(scheduleId));
    _timers.delete(scheduleId);
  }
}

function cancelAllTimers() {
  for (var timer of _timers.values()) {
    clearTimeout(timer);
  }
  _timers.clear();
}

// ── Schedule Parser (simple cron) ─────────────────────────────────
// Supports: "0 0 1 * *" (monthly), "0 9 * * 1" (weekly), "0 0 * * *" (daily)
function calculateNextRun(cronExpr) {
  var parts = cronExpr.split(' ');
  if (parts.length < 5) return null;

  var minute = parseInt(parts[0], 10);
  var hour = parseInt(parts[1], 10);
  var dayOfMonth = parts[2] === '*' ? null : parseInt(parts[2], 10);
  var month = parts[3] === '*' ? null : parseInt(parts[3], 10);
  var dayOfWeek = parts[4] === '*' ? null : parseInt(parts[4], 10);

  var now = new Date();
  var next = new Date(now);
  next.setSeconds(0);
  next.setMilliseconds(0);
  next.setMinutes(minute !== null ? minute : now.getMinutes());
  next.setHours(hour !== null ? hour : now.getHours());

  if (next <= now) {
    next.setDate(next.getDate() + 1);
  }

  if (dayOfMonth !== null && next.getDate() !== dayOfMonth) {
    next.setDate(dayOfMonth);
    if (next <= now) next.setMonth(next.getMonth() + 1);
  }

  if (month !== null && next.getMonth() + 1 !== month) {
    next.setMonth(month - 1);
    if (next <= now) next.setFullYear(next.getFullYear() + 1);
  }

  if (dayOfWeek !== null) {
    while (next.getDay() !== dayOfWeek || next <= now) {
      next.setDate(next.getDate() + 1);
    }
  }

  return next.toISOString().replace('T', ' ').substring(0, 19);
}

// ── Startup: restore all timers ──────────────────────────────────
function restoreTimers() {
  if (!_db) return;
  try {
    var stmt = _db.prepare("SELECT id, schedule, next_run_at FROM scheduled_reports WHERE enabled = 1");
    while (stmt.step()) {
      var row = stmt.getAsObject();
      if (row.next_run_at && new Date(row.next_run_at) > new Date()) {
        scheduleTimer(row.id, row.next_run_at);
      } else {
        // Overdue — run now
        runSchedule(row.id);
      }
    }
    stmt.free();
  } catch (e) {
    console.warn('[scheduled-reports] Failed to restore timers:', e.message);
  }
}

module.exports = {
  init,
  createSchedule,
  listSchedules,
  getSchedule,
  updateSchedule,
  deleteSchedule,
  runSchedule,
  getHistory,
  cancelAllTimers,
  restoreTimers,
  calculateNextRun,
};
