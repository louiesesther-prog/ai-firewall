const { getDb } = require('./db.cjs');

let _webhookDispatcher = null;

function setWebhookDispatcher(dispatcher) {
  _webhookDispatcher = dispatcher;
}

function trackScan({ source, filePath, fileType, matches, riskScore, profile, metadata }) {
  try {
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

    // Dispatch webhooks if configured
    if (_webhookDispatcher && matches.length > 0) {
      try {
        _webhookDispatcher.dispatchEvent('scan', {
          source: source || 'cli',
          filePath: filePath || null,
          matches: matches,
          riskScore: riskScore || 0,
          piiTypes: piiTypes,
          profile: profile || 'none',
        });
      } catch (e) { /* non-blocking */ }
    }

    if (_webhookDispatcher && riskScore && riskScore > 70) {
      try {
        _webhookDispatcher.dispatchEvent('high_risk', {
          source: source || 'cli',
          riskScore: riskScore,
          piiTypes: piiTypes,
        });
      } catch (e) { /* non-blocking */ }
    }

    return eventInfo.lastInsertRowid;
  } catch (e) {
    console.warn('[tracker] Analytics write failed:', e.message);
    return null;
  }
}

module.exports = { trackScan, setWebhookDispatcher };
