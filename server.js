require('dotenv').config();

const express = require('express');
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

// Stateless signed cookie session. This works reliably on Vercel/serverless,
// unlike express-session's default in-memory store which can disappear
// between API requests handled by different instances.
const SESSION_SECRET = process.env.SESSION_SECRET || 'CHANGE-ME-FREAKS';
const SESSION_COOKIE = 'freaks_session';
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;

function parseCookies(req) {
  const raw = String(req.headers.cookie || '');
  const out = {};
  for (const part of raw.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!key) continue;
    try { out[key] = decodeURIComponent(value); } catch { out[key] = value; }
  }
  return out;
}

function sessionSignature(accountId, expiresAt) {
  return crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(`${accountId}.${expiresAt}`)
    .digest('hex');
}

function makeSessionToken(accountId) {
  const expiresAt = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
  const sig = sessionSignature(accountId, expiresAt);
  return `${accountId}.${expiresAt}.${sig}`;
}

function readSessionToken(req) {
  try {
    const token = parseCookies(req)[SESSION_COOKIE];
    if (!token) return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const accountId = Number(parts[0]);
    const expiresAt = Number(parts[1]);
    const receivedSig = parts[2];
    if (!Number.isInteger(accountId) || accountId <= 0) return null;
    if (!Number.isFinite(expiresAt) || expiresAt <= Math.floor(Date.now() / 1000)) return null;
    const expectedSig = sessionSignature(accountId, expiresAt);
    const a = Buffer.from(receivedSig, 'hex');
    const b = Buffer.from(expectedSig, 'hex');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    return { accountId, expiresAt };
  } catch (_) {
    return null;
  }
}

function setAuthCookie(res, accountId) {
  const token = makeSessionToken(accountId);
  const secure = process.env.VERCEL ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}${secure}`
  );
}

function clearAuthCookie(res) {
  const secure = process.env.VERCEL ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`
  );
}

app.use((req, _res, next) => {
  const auth = readSessionToken(req);
  // Keep the existing req.session.accountId interface used by the routes.
  req.session = auth ? { accountId: auth.accountId } : {};
  next();
});

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
        'SELECT id, firstName, secondName, age, sex, adminLvl, faction, factionRank, walletMoney, bankMoney, FLCoins, hoursPlayed, warns, banned, bannedTemp, bannedReason FROM vrp_users WHERE id = ? LIMIT 1',
        [userId]
      );
      if (rows.length) identity = rows[0];
    } catch (_) {}
  }

  return { userId, identity };
}


const ADMIN_TITLES = {
  1: 'Helper In Teste',
  2: 'Helper',
  3: 'Moderator',
  4: 'Administrator',
  5: 'Supervizor',
  6: 'Head Of Staff',
  7: 'Community Manager',
  8: 'Fondator FREAKS'
};

async function getSessionContext(req) {
  const [rows] = await db.query(
    `SELECT id, license, email, fivem_name, flcoins, user_id, created_at, last_login_at
     FROM freaks_accounts WHERE id = ? LIMIT 1`,
    [req.session.accountId]
  );
  if (!rows.length) return null;
  const account = rows[0];
  const resolved = await resolveUserData(account);
  const adminLevel = Number(resolved.identity?.adminLvl || 0);
  return {
    account,
    userId: resolved.userId ? Number(resolved.userId) : null,
    identity: resolved.identity,
    adminLevel,
    isAdmin: adminLevel >= 4,
    adminTitle: ADMIN_TITLES[adminLevel] || null
  };
}

async function requireAdministrator(req, res, next) {
  try {
    const ctx = await getSessionContext(req);
    if (!ctx) return res.status(401).json({ ok: false, message: 'Sesiune expirată.' });
    if (!ctx.isAdmin) return res.status(403).json({ ok: false, message: 'Doar Administrator+ poate accesa această secțiune.' });
    req.freaksContext = ctx;
    next();
  } catch (err) {
    console.error('ADMIN CHECK ERROR:', err);
    res.status(500).json({ ok: false, message: 'Eroare server.' });
  }
}

let caseSchemaReady = false;
async function ensureCaseTables() {
  if (caseSchemaReady) return;
  await db.query(`
    CREATE TABLE IF NOT EXISTS freaks_complaints (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      account_id INT UNSIGNED NOT NULL,
      reporter_user_id INT NULL,
      reported_name VARCHAR(128) NOT NULL,
      reported_user_id INT NOT NULL,
      reason TEXT NOT NULL,
      evidence TEXT NOT NULL,
      status VARCHAR(16) NOT NULL DEFAULT 'open',
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      closed_at DATETIME NULL,
      closed_by_user_id INT NULL,
      PRIMARY KEY (id),
      KEY idx_freaks_complaints_status (status),
      KEY idx_freaks_complaints_created (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS freaks_unban_requests (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      account_id INT UNSIGNED NOT NULL,
      requester_user_id INT NULL,
      player_name VARCHAR(128) NOT NULL,
      player_id INT NOT NULL,
      reason TEXT NOT NULL,
      evidence TEXT NOT NULL,
      status VARCHAR(16) NOT NULL DEFAULT 'open',
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      closed_at DATETIME NULL,
      closed_by_user_id INT NULL,
      PRIMARY KEY (id),
      KEY idx_freaks_unban_status (status),
      KEY idx_freaks_unban_created (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);
  caseSchemaReady = true;
}

function cleanText(value, max) {
  return String(value || '').trim().slice(0, max);
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

    setAuthCookie(res, account.id);
    req.session.accountId = account.id;

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
  clearAuthCookie(res);
  res.json({ ok: true });
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
        identity: resolved.identity,
        adminLevel: Number(resolved.identity?.adminLvl || 0),
        adminTitle: ADMIN_TITLES[Number(resolved.identity?.adminLvl || 0)] || null,
        isAdmin: Number(resolved.identity?.adminLvl || 0) >= 4,
        walletMoney: Number(resolved.identity?.walletMoney || 0),
        bankMoney: Number(resolved.identity?.bankMoney || 0),
        hoursPlayed: Number(resolved.identity?.hoursPlayed || 0),
        faction: resolved.identity?.faction || 'user',
        factionRank: resolved.identity?.factionRank || 'none'
      }
    });
  } catch (err) {
    console.error('ME ERROR:', err);
    res.status(500).json({ ok: false, message: 'Eroare server.' });
  }
});


async function getLivePlayerCount() {
  try {
    const [rows] = await db.query(
      `SELECT online_players, updated_at
       FROM freaks_server_stats
       WHERE id = 1
       LIMIT 1`
    );

    if (!rows.length) return null;

    const row = rows[0];
    const updated = row.updated_at ? new Date(row.updated_at).getTime() : 0;

    // Dacă serverul nu a mai actualizat de 90 secunde, îl considerăm offline.
    if (!updated || (Date.now() - updated) > 90000) return 0;

    return Number(row.online_players || 0);
  } catch (err) {
    console.error('LIVE PLAYERS DB ERROR:', err.message);
    return null;
  }
}

async function getTotalVehicleCount() {
  // Încearcă întâi tabela standard vRP.
  const candidates = [
    'vrp_user_vehicles',
    'user_vehicles',
    'vehicles',
    'player_vehicles',
    'owned_vehicles'
  ];

  for (const table of candidates) {
    try {
      const [rows] = await db.query(`SELECT COUNT(*) AS c FROM \`${table}\``);
      if (rows && rows.length) return Number(rows[0].c || 0);
    } catch (_) {}
  }

  // Fallback: caută automat o tabelă care conține "vehicle" în baza curentă.
  try {
    const [tables] = await db.query(`
      SELECT TABLE_NAME
      FROM information_schema.TABLES
      WHERE TABLE_SCHEMA = DATABASE()
        AND LOWER(TABLE_NAME) LIKE '%vehicle%'
      ORDER BY
        CASE WHEN LOWER(TABLE_NAME) = 'vrp_user_vehicles' THEN 0 ELSE 1 END,
        TABLE_NAME
    `);

    for (const row of tables) {
      const table = row.TABLE_NAME;
      if (!/^[A-Za-z0-9_]+$/.test(table)) continue;

      try {
        const [rows] = await db.query(`SELECT COUNT(*) AS c FROM \`${table}\``);
        if (rows && rows.length) return Number(rows[0].c || 0);
      } catch (_) {}
    }
  } catch (err) {
    console.error('VEHICLE TABLE DETECT ERROR:', err.message);
  }

  return null;
}


app.post('/api/complaints', requireAuth, async (req, res) => {
  try {
    await ensureCaseTables();
    const ctx = await getSessionContext(req);
    if (!ctx) return res.status(401).json({ ok: false, message: 'Sesiune expirată.' });

    const reportedName = cleanText(req.body.reportedName, 128);
    const reportedId = Number(req.body.reportedId);
    const reason = cleanText(req.body.reason, 4000);
    const evidence = cleanText(req.body.evidence, 4000);

    if (!reportedName || !Number.isInteger(reportedId) || reportedId <= 0 || reason.length < 5 || evidence.length < 3) {
      return res.status(400).json({ ok: false, message: 'Completează numele, ID-ul, motivul și dovada.' });
    }

    const [result] = await db.query(
      `INSERT INTO freaks_complaints
       (account_id, reporter_user_id, reported_name, reported_user_id, reason, evidence)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [req.session.accountId, ctx.userId, reportedName, reportedId, reason, evidence]
    );

    res.json({ ok: true, id: result.insertId, message: 'Reclamația a fost trimisă.' });
  } catch (err) {
    console.error('CREATE COMPLAINT ERROR:', err);
    res.status(500).json({ ok: false, message: 'Nu am putut trimite reclamația.' });
  }
});

app.get('/api/complaints', requireAuth, requireAdministrator, async (req, res) => {
  try {
    await ensureCaseTables();
    const [rows] = await db.query(`
      SELECT c.*, a.email AS reporter_email,
             u.firstName AS reporter_first_name, u.secondName AS reporter_second_name
      FROM freaks_complaints c
      LEFT JOIN freaks_accounts a ON a.id = c.account_id
      LEFT JOIN vrp_users u ON u.id = c.reporter_user_id
      ORDER BY CASE WHEN c.status = 'open' THEN 0 ELSE 1 END, c.created_at DESC
      LIMIT 250
    `);
    res.json({ ok: true, items: rows });
  } catch (err) {
    console.error('LIST COMPLAINTS ERROR:', err);
    res.status(500).json({ ok: false, message: 'Nu am putut încărca reclamațiile.' });
  }
});

app.patch('/api/complaints/:id/close', requireAuth, requireAdministrator, async (req, res) => {
  try {
    await ensureCaseTables();
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ ok: false });
    await db.query(
      `UPDATE freaks_complaints
       SET status = 'closed', closed_at = NOW(), closed_by_user_id = ?
       WHERE id = ? AND status <> 'closed'`,
      [req.freaksContext.userId, id]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('CLOSE COMPLAINT ERROR:', err);
    res.status(500).json({ ok: false, message: 'Nu am putut închide reclamația.' });
  }
});

app.post('/api/unban-requests', requireAuth, async (req, res) => {
  try {
    await ensureCaseTables();
    const ctx = await getSessionContext(req);
    if (!ctx) return res.status(401).json({ ok: false, message: 'Sesiune expirată.' });

    const playerName = cleanText(req.body.playerName, 128);
    const playerId = Number(req.body.playerId);
    const reason = cleanText(req.body.reason, 4000);
    const evidence = cleanText(req.body.evidence, 4000);

    if (!playerName || !Number.isInteger(playerId) || playerId <= 0 || reason.length < 5 || evidence.length < 3) {
      return res.status(400).json({ ok: false, message: 'Completează numele, ID-ul, motivul și dovada.' });
    }

    const [result] = await db.query(
      `INSERT INTO freaks_unban_requests
       (account_id, requester_user_id, player_name, player_id, reason, evidence)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [req.session.accountId, ctx.userId, playerName, playerId, reason, evidence]
    );

    res.json({ ok: true, id: result.insertId, message: 'Cererea de unban a fost trimisă.' });
  } catch (err) {
    console.error('CREATE UNBAN ERROR:', err);
    res.status(500).json({ ok: false, message: 'Nu am putut trimite cererea.' });
  }
});

app.get('/api/unban-requests', requireAuth, requireAdministrator, async (req, res) => {
  try {
    await ensureCaseTables();
    const [rows] = await db.query(`
      SELECT r.*, a.email AS requester_email,
             u.firstName AS account_first_name, u.secondName AS account_second_name
      FROM freaks_unban_requests r
      LEFT JOIN freaks_accounts a ON a.id = r.account_id
      LEFT JOIN vrp_users u ON u.id = r.requester_user_id
      ORDER BY CASE WHEN r.status = 'open' THEN 0 ELSE 1 END, r.created_at DESC
      LIMIT 250
    `);
    res.json({ ok: true, items: rows });
  } catch (err) {
    console.error('LIST UNBAN ERROR:', err);
    res.status(500).json({ ok: false, message: 'Nu am putut încărca cererile.' });
  }
});

app.patch('/api/unban-requests/:id/close', requireAuth, requireAdministrator, async (req, res) => {
  try {
    await ensureCaseTables();
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ ok: false });
    await db.query(
      `UPDATE freaks_unban_requests
       SET status = 'closed', closed_at = NOW(), closed_by_user_id = ?
       WHERE id = ? AND status <> 'closed'`,
      [req.freaksContext.userId, id]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('CLOSE UNBAN ERROR:', err);
    res.status(500).json({ ok: false, message: 'Nu am putut închide cererea.' });
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

    // Numărul REAL de jucători conectați în acest moment.
    stats.connected = await getLivePlayerCount();

    // Total vehicule din garajele tuturor jucătorilor.
    stats.vehicles = await getTotalVehicleCount();

    // Case / proprietăți, dacă există tabela standard.
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
