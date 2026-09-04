const loginView = document.getElementById('loginView');
const appView = document.getElementById('appView');
const loginForm = document.getElementById('loginForm');
const loginError = document.getElementById('loginError');

let currentUser = null;

const fmtDate = (value) => {
  if (!value) return '—';
  try { return new Date(value).toLocaleString('ro-RO'); } catch { return '—'; }
};

async function api(url, options = {}) {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.message || data.error || 'Eroare');
  return data;
}

function showApp() {
  loginView.classList.add('hidden');
  appView.classList.remove('hidden');
}

function showLogin() {
  appView.classList.add('hidden');
  loginView.classList.remove('hidden');
}

function fillUser(user) {
  currentUser = user;
  const idText = user.userId ? `ID ${user.userId}` : `ACC ${user.accountId}`;
  document.getElementById('topName').textContent = user.displayName;
  document.getElementById('topId').textContent = idText;
  document.getElementById('topCoins').textContent = user.flcoins;

  document.getElementById('quickName').textContent = user.displayName;
  document.getElementById('quickEmail').textContent = user.email;
  document.getElementById('quickCoins').textContent = user.flcoins;
  document.getElementById('activityName').textContent = user.displayName;

  document.getElementById('profileName').textContent = user.displayName;
  document.getElementById('profileEmail').textContent = user.email;
  document.getElementById('profileEmail2').textContent = user.email;
  document.getElementById('profileId').textContent = user.userId || `ACC ${user.accountId}`;
  document.getElementById('profileCoins').textContent = `${user.flcoins} FLCoins`;
  document.getElementById('lastLogin').textContent = fmtDate(user.lastLoginAt);
  document.getElementById('createdAt').textContent = fmtDate(user.createdAt);

  const identity = user.identity;
  document.getElementById('characterName').textContent =
    identity ? [identity.firstName, identity.secondName].filter(Boolean).join(' ') : '—';
}

async function loadDashboard() {
  const data = await api('/api/dashboard');
  const s = data.stats || {};
  document.getElementById('statRegistered').textContent = s.registered ?? 0;
  document.getElementById('statConnected').textContent = s.connected ?? '—';
  document.getElementById('statVehicles').textContent = s.vehicles ?? '—';
  document.getElementById('statHouses').textContent = s.houses ?? '—';
}

async function loadSession() {
  try {
    const data = await api('/api/me');
    fillUser(data.user);
    showApp();
    await loadDashboard();
  } catch {
    showLogin();
  }
}

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  loginError.textContent = '';
  const btn = loginForm.querySelector('button[type=submit]');
  btn.disabled = true;
  btn.textContent = 'SE CONECTEAZĂ...';

  try {
    await api('/api/login', {
      method: 'POST',
      body: JSON.stringify({
        email: document.getElementById('email').value,
        password: document.getElementById('password').value
      })
    });
    await loadSession();
  } catch (err) {
    loginError.textContent = err.message;
  } finally {
    btn.disabled = false;
    btn.textContent = 'LOGIN';
  }
});

document.getElementById('logoutBtn').addEventListener('click', async () => {
  try { await api('/api/logout', { method: 'POST' }); } catch {}
  showLogin();
});

function openPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));
  document.getElementById(name === 'profile' ? 'profilePage' : 'homePage').classList.remove('hidden');
  document.querySelectorAll('.nav-link[data-page]').forEach(b => {
    b.classList.toggle('active', b.dataset.page === name);
  });
}

document.querySelectorAll('.nav-link[data-page]').forEach(btn => {
  btn.addEventListener('click', () => openPage(btn.dataset.page));
});

document.querySelectorAll('[data-open-profile]').forEach(btn => {
  btn.addEventListener('click', () => openPage('profile'));
});

document.getElementById('profileMenuBtn').addEventListener('click', () => openPage('profile'));

loadSession();