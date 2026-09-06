require('dotenv').config();

const express = require('express');
const session = require('express-session');
const mysql = require('mysql2/promise');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);

const db = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'freaks',
  waitForConnections: true,
  connectionLimit: 10,
  charset: 'utf8mb4'
});

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'CHANGE-ME-FREAKS',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function verifyPassword(password, saltHex, expectedHashHex) {
  try {
    const salt = Buffer.from(String(saltHex || ''), 'hex');
    const expected = Buffer.from(String(expectedHashHex || ''), 'hex');
    const actual = crypto.scryptSync(String(password || ''), salt, expected.length || 64);
    if (actual.length !== expected.length) return false;
    return crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function requireAuth(req, res, next) {
  if (!req.session.accountId) {
    return res.status(401).json({ ok: false, error: 'NOT_AUTHENTICATED' });
  }
  next();
}

async function resolveUserData(account) {
  let userId = account.user_id || null;
  let identity = null;

  // Fallback for standard vRP installations:
  // tries to resolve the user id through vrp_user_ids using the FiveM license.
  if (!userId && account.license) {
    try {
      const [idRows] = await db.query(
        'SELECT user_id FROM vrp_user_ids WHERE identifier = ? LIMIT 1',
        [account.license]
      );
      if (idRows.length) userId = idRows[0].user_id;
    } catch (_) {}
  }

  if (userId) {
    try {
      const [rows] = await db.query(
        'SELECT id, firstName, secondName, age, sex FROM vrp_users WHERE id = ? LIMIT 1',
        [userId]
      );
      if (rows.length) identity = rows[0];
    } catch (_) {}
  }

  return { userId, identity };
}

app.post('/api/login', async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || '');

  if (!email || password.length < 6) {
    return res.status(400).json({ ok: false, message: 'Email sau parolă invalidă.' });
  }

  try {
    const [rows] = await db.query(
      `SELECT id, license, email, password_hash, password_salt,
              fivem_name, flcoins, user_id, created_at, last_login_at
       FROM freaks_accounts
       WHERE email = ?
       LIMIT 1`,
      [email]
    );

    if (!rows.length) {
      return res.status(401).json({ ok: false, message: 'Contul nu există.' });
    }

    const account = rows[0];
    if (!verifyPassword(password, account.password_salt, account.password_hash)) {
      return res.status(401).json({ ok: false, message: 'Parolă greșită.' });
    }

    req.session.accountId = account.id;
    req.session.email = account.email;

    return res.json({ ok: true });
  } catch (err) {
    console.error('LOGIN ERROR:', err);
    return res.status(500).json({
      ok: false,
      message: 'Eroare la baza de date. Rulează migration.sql și verifică .env.'
    });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT id, license, email, fivem_name, flcoins, user_id,
              created_at, last_login_at
       FROM freaks_accounts
       WHERE id = ?
       LIMIT 1`,
      [req.session.accountId]
    );

    if (!rows.length) return res.status(401).json({ ok: false });

    const account = rows[0];
    const resolved = await resolveUserData(account);

    const displayName =
      account.fivem_name ||
      (resolved.identity
        ? [resolved.identity.firstName, resolved.identity.secondName].filter(Boolean).join(' ')
        : null) ||
      account.email.split('@')[0];

    res.json({
      ok: true,
      user: {
        accountId: account.id,
        userId: resolved.userId,
        displayName,
        email: account.email,
        flcoins: Number(account.flcoins || 0),
        createdAt: account.created_at,
        lastLoginAt: account.last_login_at,
        identity: resolved.identity
      }
    });
  } catch (err) {
    console.error('ME ERROR:', err);
    res.status(500).json({ ok: false, message: 'Eroare server.' });
  }
});

app.get('/api/dashboard', requireAuth, async (req, res) => {
  const stats = {
    registered: 0,
    connected: null,
    vehicles: null,
    houses: null
  };

  try {
    const [[registered]] = await db.query('SELECT COUNT(*) AS c FROM freaks_accounts');
    stats.registered = Number(registered.c || 0);

    // Optional tables. If they don't exist, the UI shows "—".
    try {
      const [[vehicles]] = await db.query('SELECT COUNT(*) AS c FROM vrp_user_vehicles');
      stats.vehicles = Number(vehicles.c || 0);
    } catch (_) {}

    try {
      const [[houses]] = await db.query('SELECT COUNT(*) AS c FROM vrp_user_homes');
      stats.houses = Number(houses.c || 0);
    } catch (_) {}

    res.json({
      ok: true,
      stats,
      serverName: process.env.SERVER_NAME || 'Freaks Romania'
    });
  } catch (err) {
    console.error('DASHBOARD ERROR:', err);
    res.status(500).json({ ok: false });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`[Freaks Panel] http://localhost:${PORT}`);
  });
}

module.exports = app;
