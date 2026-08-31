// ── Retention Policy Enforcer ─────────────────────────────────────
// Auto-expires audit events and compliance reports based on retention policies.

var _db = null;

function init(database) {
  _db = database;
}

function cleanupExpired(retentionDays) {
  if (!_db) return { deleted: 0 };
  retentionDays = retentionDays || 365;

  var cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - retentionDays);
  var cutoffStr = cutoffDate.toISOString().replace('T', ' ').substring(0, 19);

  var deleted = 0;

  try {
    // Delete audit events older than retention period
    var stmt1 = _db.prepare('DELETE FROM audit_events WHERE timestamp < ?');
    stmt1.run([cutoffStr]);
    deleted += stmt1.getRowsModified ? stmt1.getRowsModified() : 0;
    stmt1.free();
  } catch (e) {
    console.warn('[retention] Failed to clean audit_events:', e.message);
  }

  try {
    // Delete old compliance reports (keep for double the retention)
    var reportCutoff = new Date();
    reportCutoff.setDate(reportCutoff.getDate() - (retentionDays * 2));
    var reportCutoffStr = reportCutoff.toISOString().replace('T', ' ').substring(0, 19);

    var stmt2 = _db.prepare('DELETE FROM compliance_reports WHERE created_at < ?');
    stmt2.run([reportCutoffStr]);
    stmt2.free();
  } catch (e) {
    console.warn('[retention] Failed to clean compliance_reports:', e.message);
  }

  try {
    // Delete old webhook deliveries (keep 30 days)
    var deliveryCutoff = new Date();
    deliveryCutoff.setDate(deliveryCutoff.getDate() - 30);
    var deliveryCutoffStr = deliveryCutoff.toISOString().replace('T', ' ').substring(0, 19);

    var stmt3 = _db.prepare('DELETE FROM webhook_deliveries WHERE created_at < ?');
    stmt3.run([deliveryCutoffStr]);
    stmt3.free();
  } catch (e) {
    console.warn('[retention] Failed to clean webhook_deliveries:', e.message);
  }

  return { deleted: deleted, cutoffDate: cutoffStr };
}

function getRetentionStats() {
  if (!_db) return {};

  var stats = {};

  try {
    var stmt = _db.prepare('SELECT COUNT(*) as count FROM audit_events');
    if (stmt.step()) stats.auditEvents = stmt.getAsObject().count;
    stmt.free();
  } catch (e) { stats.auditEvents = 0; }

  try {
    var stmt2 = _db.prepare('SELECT COUNT(*) as count FROM compliance_reports');
    if (stmt2.step()) stats.complianceReports = stmt2.getAsObject().count;
    stmt2.free();
  } catch (e) { stats.complianceReports = 0; }

  try {
    var stmt3 = _db.prepare('SELECT COUNT(*) as count FROM webhook_deliveries');
    if (stmt3.step()) stats.webhookDeliveries = stmt3.getAsObject().count;
    stmt3.free();
  } catch (e) { stats.webhookDeliveries = 0; }

  try {
    var stmt4 = _db.prepare('SELECT MIN(timestamp) as oldest, MAX(timestamp) as newest FROM audit_events');
    if (stmt4.step()) {
      var row = stmt4.getAsObject();
      stats.oldestEvent = row.oldest;
      stats.newestEvent = row.newest;
    }
    stmt4.free();
  } catch (e) {}

  return stats;
}

module.exports = { init, cleanupExpired, getRetentionStats };
