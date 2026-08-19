const { getDb } = require('./db');

function getTrendData(days = 30) {
  const database = getDb();
  return database.prepare(`
    SELECT date(timestamp) as day, COUNT(*) as scans, SUM(total_matches) as pii_count
    FROM scan_events
    WHERE timestamp >= datetime('now', '-' || ? || ' days')
    GROUP BY day ORDER BY day
  `).all(days);
}

function getTopPIITypes(limit = 10) {
  const database = getDb();
  return database.prepare(`
    SELECT pii_type, COUNT(*) as count, AVG(confidence) as avg_conf
    FROM pii_detections GROUP BY pii_type ORDER BY count DESC LIMIT ?
  `).all(limit);
}

function getRiskDistribution() {
  const database = getDb();
  return database.prepare(`
    SELECT
      CASE WHEN risk_score >= 50 THEN 'high'
           WHEN risk_score >= 20 THEN 'medium'
           ELSE 'low' END as level,
      COUNT(*) as count
    FROM scan_events GROUP BY level
  `).all();
}

function getRecentScans(limit = 20) {
  const database = getDb();
  return database.prepare(`
    SELECT id, timestamp, source, file_path, file_type, total_matches, risk_score, pii_types, profile
    FROM scan_events ORDER BY id DESC LIMIT ?
  `).all(limit);
}

function getSummary() {
  const database = getDb();
  const totals = database.prepare(`
    SELECT COUNT(*) as total_scans, SUM(total_matches) as total_pii, AVG(risk_score) as avg_risk
    FROM scan_events
  `).get();
  const today = database.prepare(`
    SELECT COUNT(*) as scans, SUM(total_matches) as pii
    FROM scan_events WHERE date(timestamp) = date('now')
  `).get();
  const bySource = database.prepare(`
    SELECT source, COUNT(*) as count FROM scan_events GROUP BY source
  `).all();
  return { totals, today, bySource };
}

function getHeatmapData(days = 30) {
  const database = getDb();
  return database.prepare(`
    SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
    FROM scan_events
    WHERE timestamp >= datetime('now', '-' || ? || ' days')
    GROUP BY hour ORDER BY hour
  `).all(days);
}

module.exports = { getTrendData, getTopPIITypes, getRiskDistribution, getRecentScans, getSummary, getHeatmapData };
