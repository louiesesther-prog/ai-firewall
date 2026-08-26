#!/usr/bin/env node
// AI Firewall Cloud SaaS — entry point
// Usage: node saas/index.js [--port 3000] [--jwt-secret <secret>]

const path = require('path');
const express = require('express');
const { getDb, closeDb } = require('./db.cjs');
const routes = require('./routes.cjs');

const PORT = parseInt(process.env.PORT, 10) || 3000;

const app = express();
app.use(express.json({ limit: '1mb' }));

// ── Security headers ──────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.removeHeader('X-Powered-By');
  next();
});

// ── CORS ───────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── Static files ──────────────────────────────────────────
app.use('/saas', express.static(path.join(__dirname)));

// ── API routes ────────────────────────────────────────────
app.use('/api', routes);

// ── HTML pages ────────────────────────────────────────────
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));

// ── Health check ──────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', version: '2.1.0', mode: 'cloud' });
});

// ── Error handler ─────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[SaaS Error]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Start ─────────────────────────────────────────────────
if (require.main === module) {
  process.on('uncaughtException', (err) => { console.error('Uncaught:', err.message); process.exit(1); });
  process.on('unhandledRejection', (err) => { console.error('Unhandled:', err && err.message ? err.message : err); });

  (async () => {
    try { await getDb(); } catch (e) { console.error('Database init failed:', e.message); process.exit(1); }

    const server = app.listen(PORT, () => {
      console.log('┌─────────────────────────────────────────────┐');
      console.log('│  AI Firewall Cloud SaaS                     │');
      console.log('├─────────────────────────────────────────────┤');
      console.log('│  Dashboard: http://localhost:' + PORT + '/dashboard    │');
      console.log('│  Login:     http://localhost:' + PORT + '/login        │');
      console.log('│  Register:  http://localhost:' + PORT + '/register     │');
      console.log('│  API:       http://localhost:' + PORT + '/api/health    │');
      console.log('├─────────────────────────────────────────────┤');
      console.log('│  Press Ctrl+C to stop                       │');
      console.log('└─────────────────────────────────────────────┘');
    });

    process.on('SIGINT', () => { closeDb(); server.close(); process.exit(0); });
    process.on('SIGTERM', () => { closeDb(); server.close(); process.exit(0); });
  })();
}

module.exports = app;
