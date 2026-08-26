const crypto = require('crypto');
const { getDb, run, get } = require('./db.cjs');

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

// ── Password Hashing (scrypt, zero deps) ─────────────────────
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return salt + ':' + hash;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const test = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(test, 'hex'));
}

// ── JWT (zero deps) ──────────────────────────────────────────
function base64url(buf) {
  return (Buffer.isBuffer(buf) ? buf : Buffer.from(buf))
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function signJwt(payload) {
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64url(JSON.stringify(payload));
  const sig = base64url(
    crypto.createHmac('sha256', JWT_SECRET).update(header + '.' + body).digest()
  );
  return header + '.' + body + '.' + sig;
}

function verifyJwt(token) {
  try {
    const [header, body, sig] = token.split('.');
    const expected = base64url(
      crypto.createHmac('sha256', JWT_SECRET).update(header + '.' + body).digest()
    );
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64').toString());
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

// ── User Operations ───────────────────────────────────────────
function generateId() {
  return crypto.randomBytes(12).toString('hex');
}

function createUser({ email, name, password }) {
  getDb();
  const existing = get('SELECT id FROM users WHERE email = ?', [email.toLowerCase().trim()]);
  if (existing) throw new Error('Email already registered');

  const id = generateId();
  const passwordHash = hashPassword(password);

  run(
    'INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)',
    [id, email.toLowerCase().trim(), name.trim(), passwordHash]
  );

  return { id, email: email.toLowerCase().trim(), name: name.trim(), plan: 'free' };
}

function authenticateUser({ email, password }) {
  getDb();
  const user = get('SELECT * FROM users WHERE email = ?', [email.toLowerCase().trim()]);
  if (!user) return null;
  if (!verifyPassword(password, user.password_hash)) return null;

  run('UPDATE users SET last_login_at = datetime("now") WHERE id = ?', [user.id]);

  return {
    id: user.id, email: user.email, name: user.name,
    plan: user.plan, status: user.status, avatar_url: user.avatar_url
  };
}

function getUserById(id) {
  getDb();
  return get('SELECT id, email, name, plan, status, avatar_url, created_at, last_login_at FROM users WHERE id = ?', [id]) || null;
}

function updateUser(id, updates) {
  getDb();
  const fields = [];
  const values = [];
  for (const [key, val] of Object.entries(updates)) {
    if (['name', 'avatar_url', 'plan', 'status'].includes(key) && val !== undefined) {
      fields.push(key + ' = ?');
      values.push(val);
    }
  }
  if (fields.length === 0) return;
  fields.push('updated_at = datetime("now")');
  values.push(id);
  run('UPDATE users SET ' + fields.join(', ') + ' WHERE id = ?', values);
}

function changePassword(id, oldPassword, newPassword) {
  getDb();
  const user = get('SELECT password_hash FROM users WHERE id = ?', [id]);
  if (!user) throw new Error('User not found');
  if (!verifyPassword(oldPassword, user.password_hash)) throw new Error('Current password is incorrect');
  const newHash = hashPassword(newPassword);
  run('UPDATE users SET password_hash = ?, updated_at = datetime("now") WHERE id = ?', [newHash, id]);
}

// ── Auth Middleware ───────────────────────────────────────────
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  const payload = verifyJwt(authHeader.slice(7));
  if (!payload) return res.status(401).json({ error: 'Invalid or expired token.' });
  req.user = payload;
  next();
}

function optionalAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const payload = verifyJwt(authHeader.slice(7));
    if (payload) req.user = payload;
  }
  next();
}

function generateToken(user) {
  return signJwt({
    sub: user.id, email: user.email, name: user.name, plan: user.plan,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60
  });
}

module.exports = {
  hashPassword, verifyPassword, signJwt, verifyJwt,
  createUser, authenticateUser, getUserById, updateUser, changePassword,
  authMiddleware, optionalAuth, generateToken, generateId
};
