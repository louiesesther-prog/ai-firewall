const fs = require('fs');
const path = require('path');

const CLOUD_DB_PATH = path.join(
  process.env.HOME || process.env.USERPROFILE || '.',
  '.ai-firewall', 'cloud.db'
);

let db = null;
let SQL = null;

async function ensureSqlJs() {
  if (SQL) return;
  try {
    const initSqlJs = require('sql.js');
    SQL = await initSqlJs();
  } catch (e) {
    throw new Error('Cloud SaaS requires sql.js: npm install sql.js');
  }
}

async function getDb() {
  if (db) return db;
  await ensureSqlJs();

  const dir = path.dirname(CLOUD_DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  let sqlBuf = null;
  if (fs.existsSync(CLOUD_DB_PATH)) {
    sqlBuf = fs.readFileSync(CLOUD_DB_PATH);
  }

  db = sqlBuf ? new SQL.Database(sqlBuf) : new SQL.Database();
  initSchema(db);
  saveDb();
  return db;
}

function saveDb() {
  if (!db) return;
  try {
    const data = db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(CLOUD_DB_PATH, buffer);
  } catch (e) {
    console.error('[db] Failed to save database:', e.message);
  }
}

function scheduleSave() {
  setTimeout(saveDb, 100);
}

function run(sql, params = []) {
  db.run(sql, params);
  scheduleSave();
}

function get(sql, params = []) {
  const stmt = db.prepare(sql);
  if (params.length) stmt.bind(params);
  let row = null;
  if (stmt.step()) row = stmt.getAsObject();
  stmt.free();
  return row;
}

function all(sql, params = []) {
  const stmt = db.prepare(sql);
  if (params.length) stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function initSchema(database) {
  database.run('PRAGMA journal_mode = WAL');
  database.run('PRAGMA foreign_keys = ON');

  database.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      plan TEXT DEFAULT 'free',
      status TEXT DEFAULT 'active',
      avatar_url TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      last_login_at TEXT
    );

    CREATE TABLE IF NOT EXISTS teams (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      owner_id TEXT NOT NULL,
      plan TEXT DEFAULT 'free',
      settings TEXT DEFAULT '{}',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS team_members (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      role TEXT DEFAULT 'member',
      status TEXT DEFAULT 'active',
      joined_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS invitations (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      email TEXT NOT NULL,
      role TEXT DEFAULT 'member',
      invited_by TEXT NOT NULL,
      token TEXT UNIQUE NOT NULL,
      status TEXT DEFAULT 'pending',
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS api_keys (
      id TEXT PRIMARY KEY,
      team_id TEXT,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      key_hash TEXT NOT NULL,
      key_prefix TEXT NOT NULL,
      scopes TEXT DEFAULT '["scan"]',
      last_used_at TEXT,
      expires_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      team_id TEXT,
      user_id TEXT,
      source TEXT NOT NULL,
      file_path TEXT,
      total_matches INTEGER DEFAULT 0,
      risk_score INTEGER DEFAULT 0,
      pii_types TEXT DEFAULT '[]',
      profile TEXT DEFAULT 'none',
      mode TEXT DEFAULT 'placeholder',
      result TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS subscriptions (
      id TEXT PRIMARY KEY,
      team_id TEXT,
      user_id TEXT NOT NULL,
      plan TEXT NOT NULL DEFAULT 'free',
      status TEXT DEFAULT 'active',
      stripe_customer_id TEXT,
      stripe_subscription_id TEXT,
      current_period_start TEXT,
      current_period_end TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
}

function closeDb() {
  if (db) { saveDb(); db.close(); db = null; }
}

module.exports = { getDb, closeDb, run, get, all, saveDb, CLOUD_DB_PATH };
