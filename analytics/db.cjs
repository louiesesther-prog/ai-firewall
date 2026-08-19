const fs = require('fs');
const path = require('path');

const DEFAULT_DB_DIR = path.join(process.env.HOME || process.env.USERPROFILE || '.', '.ai-firewall');
const DEFAULT_DB_PATH = path.join(DEFAULT_DB_DIR, 'analytics.db');

let db = null;

function getDbPath(configPath) {
  if (configPath) return configPath;
  return DEFAULT_DB_PATH;
}

function ensureDbDir(dbPath) {
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function getDb(dbPath) {
  if (db) return db;
  const resolvedPath = getDbPath(dbPath);
  ensureDbDir(resolvedPath);
  try {
    const Database = require('better-sqlite3');
    db = new Database(resolvedPath);
    initSchema(db);
    return db;
  } catch (e) {
    throw new Error(
      'Analytics requires better-sqlite3: npm install better-sqlite3\n' +
      'Error: ' + e.message
    );
  }
}

function initSchema(database) {
  database.pragma('journal_mode = WAL');
  database.pragma('foreign_keys = ON');

  database.exec(`
    CREATE TABLE IF NOT EXISTS scan_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL DEFAULT (datetime('now')),
      source TEXT NOT NULL,
      file_path TEXT,
      file_type TEXT,
      total_matches INTEGER NOT NULL,
      risk_score INTEGER,
      pii_types TEXT,
      profile TEXT DEFAULT 'none',
      metadata TEXT
    );

    CREATE TABLE IF NOT EXISTS pii_detections (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id INTEGER REFERENCES scan_events(id) ON DELETE CASCADE,
      pii_type TEXT NOT NULL,
      confidence REAL NOT NULL,
      file_path TEXT,
      line INTEGER,
      column INTEGER
    );

    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON scan_events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_events_source ON scan_events(source);
    CREATE INDEX IF NOT EXISTS idx_detections_type ON pii_detections(pii_type);
    CREATE INDEX IF NOT EXISTS idx_detections_event ON pii_detections(event_id);
  `);
}

function closeDb() {
  if (db) {
    db.close();
    db = null;
  }
}

module.exports = { getDb, closeDb, getDbPath };
