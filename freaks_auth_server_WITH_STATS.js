const crypto = require('crypto');

const RESOURCE = GetCurrentResourceName();
const sessions = new Set();

function getIdentifiers(src) {
    const count = GetNumPlayerIdentifiers(src);
    const ids = [];
    for (let i = 0; i < count; i++) {
        ids.push(GetPlayerIdentifier(src, i));
    }
    return ids;
}

function getLicense(src) {
    return getIdentifiers(src).find(id => id.startsWith('license:')) || null;
}

function normalizeEmail(email) {
    return String(email || '').trim().toLowerCase();
}

function validEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 190;
}

function validPassword(password) {
    return typeof password === 'string' && password.length >= 6 && password.length <= 128;
}

function makePasswordHash(password, saltHex = null) {
    const salt = saltHex ? Buffer.from(saltHex, 'hex') : crypto.randomBytes(16);
    const hash = crypto.scryptSync(password, salt, 64);

    return {
        salt: salt.toString('hex'),
        hash: hash.toString('hex')
    };
}

function verifyPassword(password, saltHex, expectedHashHex) {
    try {
        const result = makePasswordHash(password, saltHex);
        const a = Buffer.from(result.hash, 'hex');
        const b = Buffer.from(expectedHashHex, 'hex');

        if (a.length !== b.length) return false;
        return crypto.timingSafeEqual(a, b);
    } catch (e) {
        return false;
    }
}

/*
    OXMYSQL JS FIX:
    Nu folosim "MySQL.single" / "MySQL.query", deoarece globalul MySQL
    nu exista automat in runtime-ul JS FiveM.
    Folosim exportul oxmysql si il impachetam intr-un Promise.
*/
function dbQuery(sql, params = []) {
    return new Promise((resolve, reject) => {
        try {
            exports.oxmysql.query(sql, params, (result) => {
                resolve(result || []);
            });
        } catch (err) {
            reject(err);
        }
    });
}

async function dbSingle(sql, params = []) {
    const rows = await dbQuery(sql, params);
    if (!rows || !rows.length) return null;
    return rows[0];
}

function notify(src, message, kind = 'error') {
    emitNet('freaks_login:notify', src, message, kind);
}

function openCorrectScreen(src, account) {
    if (account) {
        emitNet('freaks_login:show', src, 'login', account.email || '');
    } else {
        emitNet('freaks_login:show', src, 'register', '');
    }
}

onNet('freaks_login:requestState', async (force = false) => {
    const src = global.source;
    const license = getLicense(src);

    if (!license) {
        notify(src, 'Nu am putut identifica licenta FiveM.');
        console.log(`[${RESOURCE}] No license found for source ${src}`);
        return;
    }

    try {
        console.log(
            `[${RESOURCE}] Login state requested by ${GetPlayerName(src)} (${license})${force ? ' [TEST]' : ''}`
        );

        const account = await dbSingle(
            'SELECT id, email FROM freaks_accounts WHERE license = ? LIMIT 1',
            [license]
        );

        openCorrectScreen(src, account);
    } catch (err) {
        console.error(`[${RESOURCE}] requestState DB error:`, err);

        // IMPORTANT: nu mai dam DropPlayer.
        // Afisam eroarea in joc, ca sa poti vedea problema fara sa fii scos.
        notify(src, 'Eroare baza de date. Verifica oxmysql si tabela freaks_accounts.');
    }
});

onNet('freaks_login:register', async (payload) => {
    const src = global.source;

    if (sessions.has(src)) {
        emitNet('freaks_login:success', src);
        return;
    }

    const license = getLicense(src);
    if (!license) {
        return notify(src, 'Licenta FiveM lipseste.');
    }

    const email = normalizeEmail(payload?.email);
    const password = String(payload?.password || '');

    if (!validEmail(email)) {
        return notify(src, 'Introdu un email valid.');
    }

    if (!validPassword(password)) {
        return notify(src, 'Parola trebuie sa aiba intre 6 si 128 de caractere.');
    }

    try {
        const existingLicense = await dbSingle(
            'SELECT id FROM freaks_accounts WHERE license = ? LIMIT 1',
            [license]
        );

        if (existingLicense) {
            const account = await dbSingle(
                'SELECT id, email FROM freaks_accounts WHERE license = ? LIMIT 1',
                [license]
            );

            openCorrectScreen(src, account);
            return notify(src, 'Ai deja cont. Introdu parola.');
        }

        const existingEmail = await dbSingle(
            'SELECT id FROM freaks_accounts WHERE email = ? LIMIT 1',
            [email]
        );

        if (existingEmail) {
            return notify(src, 'Emailul este deja folosit.');
        }

        const secured = makePasswordHash(password);

        await dbQuery(
            `INSERT INTO freaks_accounts
            (license, email, fivem_name, password_hash, password_salt, created_at, last_login_at)
            VALUES (?, ?, ?, ?, ?, NOW(), NOW())`,
            [license, email, GetPlayerName(src) || null, secured.hash, secured.salt]
        );

        sessions.add(src);

        emitNet('freaks_login:success', src);
        notify(src, 'Cont creat cu succes.', 'success');

        console.log(`[${RESOURCE}] Account created for ${GetPlayerName(src)} (${license})`);
    } catch (err) {
        console.error(`[${RESOURCE}] register DB error:`, err);
        notify(src, 'Eroare la crearea contului. Verifica consola serverului.');
    }
});

onNet('freaks_login:login', async (payload) => {
    const src = global.source;

    if (sessions.has(src)) {
        emitNet('freaks_login:success', src);
        return;
    }

    const license = getLicense(src);
    if (!license) {
        return notify(src, 'Licenta FiveM lipseste.');
    }

    const password = String(payload?.password || '');

    if (!validPassword(password)) {
        return notify(src, 'Parola este invalida.');
    }

    try {
        const account = await dbSingle(
            `SELECT id, email, password_hash, password_salt
             FROM freaks_accounts
             WHERE license = ?
             LIMIT 1`,
            [license]
        );

        if (!account) {
            emitNet('freaks_login:show', src, 'register', '');
            return notify(src, 'Nu exista cont. Creeaza unul.');
        }

        const ok = verifyPassword(
            password,
            account.password_salt,
            account.password_hash
        );

        if (!ok) {
            await dbQuery(
                `INSERT INTO freaks_login_attempts
                (license, account_id, success, created_at)
                VALUES (?, ?, 0, NOW())`,
                [license, account.id]
            );

            return notify(src, 'Parola gresita.');
        }

        await dbQuery(
            'UPDATE freaks_accounts SET last_login_at = NOW(), last_ip = ?, fivem_name = ? WHERE id = ?',
            [GetPlayerEndpoint(src) || null, GetPlayerName(src) || null, account.id]
        );

        await dbQuery(
            `INSERT INTO freaks_login_attempts
            (license, account_id, success, created_at)
            VALUES (?, ?, 1, NOW())`,
            [license, account.id]
        );

        sessions.add(src);

        emitNet('freaks_login:success', src);
        notify(src, 'Autentificare reusita.', 'success');

        console.log(`[${RESOURCE}] Login success for ${GetPlayerName(src)} (${license})`);
    } catch (err) {
        console.error(`[${RESOURCE}] login DB error:`, err);
        notify(src, 'Eroare la autentificare. Verifica consola serverului.');
    }
});

on('playerDropped', () => {
    sessions.delete(global.source);
});

on('onResourceStop', (resourceName) => {
    if (resourceName === RESOURCE) {
        sessions.clear();
    }
});



onNet('freaks_login:adminRegisterTest', async (payload) => {
    const src = global.source;
    const realLicense = getLicense(src);

    if (!realLicense) {
        return notify(src, 'Licenta FiveM lipseste.');
    }

    const email = normalizeEmail(payload?.email);
    const password = String(payload?.password || '');

    if (!validEmail(email)) {
        return notify(src, 'Introdu un email valid.');
    }

    if (!validPassword(password)) {
        return notify(src, 'Parola trebuie sa aiba intre 6 si 128 de caractere.');
    }

    try {
        const existingEmail = await dbSingle(
            'SELECT id FROM freaks_accounts WHERE email = ? LIMIT 1',
            [email]
        );

        if (existingEmail) {
            return notify(src, 'Emailul este deja folosit.');
        }

        const secured = makePasswordHash(password);

        // Cont de test separat, ca sa nu stricam contul principal legat de license:.
        const testLicense = `test:${realLicense}:${Date.now()}:${Math.floor(Math.random() * 100000)}`;

        await dbQuery(
            `INSERT INTO freaks_accounts
            (license, email, password_hash, password_salt, created_at, last_login_at)
            VALUES (?, ?, ?, ?, NOW(), NOW())`,
            [testLicense, email, secured.hash, secured.salt]
        );

        notify(src, 'Cont de test creat cu succes.', 'success');

        // Nu autentificam sesiunea pe contul de test.
        // Inchidem NUI-ul si lasam contul principal neatins.
        emitNet('freaks_login:success', src);

        console.log(`[${RESOURCE}] ADMIN TEST ACCOUNT created by ${GetPlayerName(src)} (${realLicense}) -> ${email}`);
    } catch (err) {
        console.error(`[${RESOURCE}] adminRegisterTest DB error:`, err);
        notify(src, 'Eroare la crearea contului de test.');
    }
});

exports('isAuthenticated', (src) => {
    return sessions.has(Number(src));
});

exports('getAccountBySource', async (src) => {
    src = Number(src);

    const license = getLicense(src);
    if (!license) return null;

    try {
        return await dbSingle(
            `SELECT id, license, email, created_at, last_login_at
             FROM freaks_accounts
             WHERE license = ?
             LIMIT 1`,
            [license]
        );
    } catch (err) {
        console.error(`[${RESOURCE}] getAccountBySource DB error:`, err);
        return null;
    }
});

RegisterCommand('freaksdb', async (source, args) => {
    if (source !== 0) return;

    try {
        const result = await dbQuery('SELECT 1 AS ok');
        console.log(`[${RESOURCE}] OXMYSQL TEST OK: ${JSON.stringify(result)}`);
    } catch (err) {
        console.error(`[${RESOURCE}] OXMYSQL TEST FAILED:`, err);
    }
}, true);


// ==============================
// FREAKS PANEL - LIVE SERVER STATS
// ==============================
async function ensurePanelStatsTable() {
    try {
        await dbQuery(`
            CREATE TABLE IF NOT EXISTS freaks_server_stats (
                id INT NOT NULL PRIMARY KEY,
                online_players INT NOT NULL DEFAULT 0,
                updated_at DATETIME NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        `);

        await dbQuery(`
            INSERT INTO freaks_server_stats (id, online_players, updated_at)
            VALUES (1, 0, NOW())
            ON DUPLICATE KEY UPDATE updated_at = NOW()
        `);

        console.log(`[${RESOURCE}] Panel stats table ready.`);
    } catch (err) {
        console.error(`[${RESOURCE}] Panel stats table error:`, err);
    }
}

async function updatePanelOnlineCount() {
    try {
        const count = GetPlayers().length;

        await dbQuery(`
            INSERT INTO freaks_server_stats (id, online_players, updated_at)
            VALUES (1, ?, NOW())
            ON DUPLICATE KEY UPDATE
                online_players = VALUES(online_players),
                updated_at = NOW()
        `, [count]);
    } catch (err) {
        console.error(`[${RESOURCE}] Online count update error:`, err);
    }
}

setTimeout(async () => {
    await ensurePanelStatsTable();
    await updatePanelOnlineCount();

    setInterval(updatePanelOnlineCount, 15000);
}, 3000);

