const { getDb } = require('./db');

function trackScan({ source, filePath, fileType, matches, riskScore, profile, metadata }) {
  const database = getDb();
  const piiTypes = [...new Set(matches.map(m => m.type))];

  const eventInfo = database.prepare(`
    INSERT INTO scan_events (source, file_path, file_type, total_matches, risk_score, pii_types, profile, metadata)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    source || 'cli',
    filePath || null,
    fileType || null,
    matches.length,
    riskScore || 0,
    JSON.stringify(piiTypes),
    profile || 'none',
    metadata ? JSON.stringify(metadata) : null
  );

  const insertDetection = database.prepare(`
    INSERT INTO pii_detections (event_id, pii_type, confidence, file_path, line, column)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  for (const m of matches) {
    insertDetection.run(
      eventInfo.lastInsertRowid,
      m.type,
      m.confidence,
      m.file || m.filePath || filePath || null,
      m.line || null,
      m.column || null
    );
  }

  return eventInfo.lastInsertRowid;
}

module.exports = { trackScan };
