const loginView = document.getElementById('loginView');
const appView = document.getElementById('appView');
const loginForm = document.getElementById('loginForm');
const loginError = document.getElementById('loginError');

let currentUser = null;

const fmtDate = (value) => {
  if (!value) return '—';
  try { return new Date(value).toLocaleString('ro-RO'); } catch { return '—'; }
};

const esc = (value) => String(value ?? '')
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll("'", '&#039;');

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
  document.getElementById('metricHours').textContent = Number(user.hoursPlayed || 0);

  const identity = user.identity;
  document.getElementById('characterName').textContent =
    identity ? [identity.firstName, identity.secondName].filter(Boolean).join(' ') : '—';

  // Administrator = level 4. Only Administrator+ sees case queues.
  document.getElementById('complaintAdminPanel').classList.toggle('hidden', !user.isAdmin);
  document.getElementById('unbanAdminPanel').classList.toggle('hidden', !user.isAdmin);
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
  const pageMap = {
    home: 'homePage',
    profile: 'profilePage',
    complaints: 'complaintsPage',
    unban: 'unbanPage'
  };
  document.getElementById(pageMap[name] || 'homePage').classList.remove('hidden');
  document.querySelectorAll('.nav-link[data-page]').forEach(b => {
    b.classList.toggle('active', b.dataset.page === name);
  });

  if (name === 'complaints' && currentUser?.isAdmin) loadComplaints();
  if (name === 'unban' && currentUser?.isAdmin) loadUnbanRequests();
}

document.querySelectorAll('.nav-link[data-page]').forEach(btn => {
  btn.addEventListener('click', () => openPage(btn.dataset.page));
});

document.querySelectorAll('[data-open-profile]').forEach(btn => {
  btn.addEventListener('click', () => openPage('profile'));
});

document.getElementById('profileMenuBtn').addEventListener('click', () => openPage('profile'));

function setFormMessage(id, text, ok = false) {
  const el = document.getElementById(id);
  el.textContent = text;
  el.className = `form-message ${ok ? 'ok' : 'err'}`;
}

document.getElementById('complaintForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = e.currentTarget.querySelector('button[type=submit]');
  btn.disabled = true;
  setFormMessage('complaintMessage', '');
  try {
    const data = await api('/api/complaints', {
      method: 'POST',
      body: JSON.stringify({
        reportedName: document.getElementById('complaintName').value,
        reportedId: document.getElementById('complaintId').value,
        reason: document.getElementById('complaintReason').value,
        evidence: document.getElementById('complaintEvidence').value
      })
    });
    e.currentTarget.reset();
    setFormMessage('complaintMessage', `${data.message} #${data.id}`, true);
    if (currentUser?.isAdmin) loadComplaints();
  } catch (err) {
    setFormMessage('complaintMessage', err.message);
  } finally {
    btn.disabled = false;
  }
});

document.getElementById('unbanForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = e.currentTarget.querySelector('button[type=submit]');
  btn.disabled = true;
  setFormMessage('unbanMessage', '');
  try {
    const data = await api('/api/unban-requests', {
      method: 'POST',
      body: JSON.stringify({
        playerName: document.getElementById('unbanName').value,
        playerId: document.getElementById('unbanId').value,
        reason: document.getElementById('unbanReason').value,
        evidence: document.getElementById('unbanEvidence').value
      })
    });
    e.currentTarget.reset();
    setFormMessage('unbanMessage', `${data.message} #${data.id}`, true);
    if (currentUser?.isAdmin) loadUnbanRequests();
  } catch (err) {
    setFormMessage('unbanMessage', err.message);
  } finally {
    btn.disabled = false;
  }
});

function renderComplaint(item) {
  const closed = item.status === 'closed';
  const reporter = [item.reporter_first_name, item.reporter_second_name].filter(Boolean).join(' ') || item.reporter_email || 'Cont necunoscut';
  return `
    <div class="case-item ${closed ? 'closed' : ''}">
      <div class="case-top">
        <div><div class="case-title">${esc(item.reported_name)} <span class="case-id">[ID ${esc(item.reported_user_id)}]</span></div><div class="case-id">Reclamație #${esc(item.id)}</div></div>
        <span class="case-status ${closed ? 'closed' : 'open'}">${closed ? 'ÎNCHISĂ' : 'DESCHISĂ'}</span>
      </div>
      <div class="case-meta">Trimisă de ${esc(reporter)}${item.reporter_user_id ? ` [ID ${esc(item.reporter_user_id)}]` : ''} • ${esc(fmtDate(item.created_at))}</div>
      <div class="case-block"><small>MOTIV</small><p>${esc(item.reason)}</p></div>
      <div class="case-block"><small>DOVADĂ</small><p>${esc(item.evidence)}</p></div>
      ${closed ? `<div class="case-meta">Închisă: ${esc(fmtDate(item.closed_at))}${item.closed_by_user_id ? ` • Admin ID ${esc(item.closed_by_user_id)}` : ''}</div>` : `<div class="case-actions"><button class="close-case-btn" data-close-complaint="${esc(item.id)}">ÎNCHIDE RECLAMAȚIA</button></div>`}
    </div>`;
}

function renderUnban(item) {
  const closed = item.status === 'closed';
  const accountName = [item.account_first_name, item.account_second_name].filter(Boolean).join(' ') || item.requester_email || 'Cont necunoscut';
  return `
    <div class="case-item ${closed ? 'closed' : ''}">
      <div class="case-top">
        <div><div class="case-title">${esc(item.player_name)} <span class="case-id">[ID ${esc(item.player_id)}]</span></div><div class="case-id">Cerere unban #${esc(item.id)}</div></div>
        <span class="case-status ${closed ? 'closed' : 'open'}">${closed ? 'ÎNCHISĂ' : 'DESCHISĂ'}</span>
      </div>
      <div class="case-meta">Cont: ${esc(accountName)}${item.requester_user_id ? ` [ID ${esc(item.requester_user_id)}]` : ''} • ${esc(fmtDate(item.created_at))}</div>
      <div class="case-block"><small>MOTIV</small><p>${esc(item.reason)}</p></div>
      <div class="case-block"><small>DOVADĂ</small><p>${esc(item.evidence)}</p></div>
      ${closed ? `<div class="case-meta">Închisă: ${esc(fmtDate(item.closed_at))}${item.closed_by_user_id ? ` • Admin ID ${esc(item.closed_by_user_id)}` : ''}</div>` : `<div class="case-actions"><button class="close-case-btn" data-close-unban="${esc(item.id)}">ÎNCHIDE CEREREA</button></div>`}
    </div>`;
}

async function loadComplaints() {
  const list = document.getElementById('complaintsList');
  list.innerHTML = '<div class="muted">Se încarcă...</div>';
  try {
    const data = await api('/api/complaints');
    list.innerHTML = data.items?.length ? data.items.map(renderComplaint).join('') : '<div class="empty-activity">Nu există reclamații.</div>';
  } catch (err) {
    list.innerHTML = `<div class="error-box">${esc(err.message)}</div>`;
  }
}

async function loadUnbanRequests() {
  const list = document.getElementById('unbanList');
  list.innerHTML = '<div class="muted">Se încarcă...</div>';
  try {
    const data = await api('/api/unban-requests');
    list.innerHTML = data.items?.length ? data.items.map(renderUnban).join('') : '<div class="empty-activity">Nu există cereri de unban.</div>';
  } catch (err) {
    list.innerHTML = `<div class="error-box">${esc(err.message)}</div>`;
  }
}

document.getElementById('refreshComplaints').addEventListener('click', loadComplaints);
document.getElementById('refreshUnban').addEventListener('click', loadUnbanRequests);

document.addEventListener('click', async (e) => {
  const complaintBtn = e.target.closest('[data-close-complaint]');
  if (complaintBtn) {
    complaintBtn.disabled = true;
    try {
      await api(`/api/complaints/${complaintBtn.dataset.closeComplaint}/close`, { method: 'PATCH' });
      await loadComplaints();
    } catch (err) {
      alert(err.message);
      complaintBtn.disabled = false;
    }
    return;
  }

  const unbanBtn = e.target.closest('[data-close-unban]');
  if (unbanBtn) {
    unbanBtn.disabled = true;
    try {
      await api(`/api/unban-requests/${unbanBtn.dataset.closeUnban}/close`, { method: 'PATCH' });
      await loadUnbanRequests();
    } catch (err) {
      alert(err.message);
      unbanBtn.disabled = false;
    }
  }
});

loadSession();
