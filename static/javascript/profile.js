/**
 * CyberShield — Profile Page JS
 * Path: static/javascript/profile.js
 *
 * Handles:
 *  - Auth guard (token check + 401 redirect)
 *  - Data fetching: /api/profile, /api/profile/activity, /api/profile/sessions
 *  - DOM rendering for all 4 sections
 *  - Actions: Edit Profile, Change Password, Toggle 2FA, Revoke Sessions
 *  - Modals, Toasts, Skeleton loaders, Counter animations
 */

'use strict';

/* ─────────────────────────────────────────────
   CONFIG
───────────────────────────────────────────── */
const CONFIG = {
  endpoints: {
    profile:        '/api/profile',
    activity:       '/api/profile/activity',
    sessions:       '/api/profile/sessions',
    update:         '/api/profile/update',
    changePassword: '/api/profile/change-password',
    toggle2fa:      '/api/profile/toggle-2fa',
    logoutSession:  '/api/profile/logout-session',
    logout:         '/api/auth/logout',
  },
  sessionKey: 'cyber_shield_session',
  userKey: 'cyber_shield_user',
};

/* ─────────────────────────────────────────────
   STATE
───────────────────────────────────────────── */
const state = {
  profile:  null,
  activity: null,
  sessions: [],
};

/* ─────────────────────────────────────────────
   AUTH HELPERS
───────────────────────────────────────────── */
function getToken() {
  return localStorage.getItem(CONFIG.sessionKey);
}

function authHeaders() {
  return {
    'Content-Type': 'application/json',
  };
}

function redirectToLogin(reason) {
  console.warn('[Profile] Auth redirect:', reason);
  localStorage.removeItem(CONFIG.sessionKey);
  localStorage.removeItem(CONFIG.userKey);
  window.location.href = '/login';
}

/* ─────────────────────────────────────────────
   API LAYER
───────────────────────────────────────────── */
async function apiFetch(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    headers: { ...authHeaders(), ...(options.headers || {}) },
    credentials: 'same-origin',
  });

  if (res.status === 401 || res.status === 403) {
    redirectToLogin(`Unauthorized — ${url}`);
    throw new Error('Unauthorized');
  }

  let data;
  try { data = await res.json(); } catch { data = {}; }

  if (!res.ok) throw new Error(data.message || data.error || `HTTP ${res.status}`);
  return data;
}

/* ─────────────────────────────────────────────
   FETCH FUNCTIONS
───────────────────────────────────────────── */
async function fetchProfile() {
  try {
    const data = await apiFetch(CONFIG.endpoints.profile);
    state.profile = data;
    renderProfile(data);
    renderSecurity(data);
  } catch (err) {
    if (err.message !== 'Unauthorized') {
      renderError('user-card',     'Failed to load profile', err.message);
      renderError('security-card', 'Failed to load security settings', err.message);
    }
  }
}

async function fetchActivity() {
  try {
    const data = await apiFetch(CONFIG.endpoints.activity);
    state.activity = data;
    renderActivity(data);
  } catch (err) {
    if (err.message !== 'Unauthorized') {
      renderError('activity-grid', 'Failed to load activity', err.message);
    }
  }
}

async function fetchSessions() {
  try {
    const data = await apiFetch(CONFIG.endpoints.sessions);
    state.sessions = Array.isArray(data) ? data : (data.sessions || []);
    renderSessions(state.sessions);
  } catch (err) {
    if (err.message !== 'Unauthorized') {
      renderSessionsError(err.message);
    }
  }
}

/* ─────────────────────────────────────────────
   RENDER: PROFILE HERO (Section 1)
───────────────────────────────────────────── */
function renderProfile(p) {
  // Avatar initials
  document.getElementById('avatar-initials').textContent =
    getInitials(p.full_name || p.username || 'U');

  // Hero text
  document.getElementById('hero-name').textContent = p.full_name || p.username || '—';
  document.getElementById('hero-email').innerHTML =
    `<i class="fas fa-envelope" style="font-size:0.7rem;opacity:0.7"></i> ${esc(p.email || '—')}`;

  // Tags
  const statusClass = (p.account_status || '').toLowerCase() === 'active' ? 'active' : 'inactive';
  document.getElementById('hero-tags').innerHTML = `
    ${p.role        ? `<span class="tag role"><i class="fas fa-user-shield" style="margin-right:0.25rem"></i>${esc(p.role)}</span>` : ''}
    ${p.department  ? `<span class="tag dept">${esc(p.department)}</span>` : ''}
    ${p.account_status ? `<span class="tag ${statusClass}">${esc(p.account_status)}</span>` : ''}
  `;

  // Info grid — 8 fields
  const fields = [
    { icon: 'fa-user',        label: 'Full Name',    value: p.full_name      || '—' },
    { icon: 'fa-at',          label: 'Email',        value: p.email          || '—', mono: true },
    { icon: 'fa-user-tag',    label: 'Role',         value: p.role           || '—' },
    { icon: 'fa-building',    label: 'Department',   value: p.department     || '—' },
    { icon: 'fa-circle-dot',  label: 'Status',       value: p.account_status || '—', statusColor: p.account_status },
    { icon: 'fa-fingerprint', label: 'User ID',      value: p.user_id || p.id || '—', mono: true },
    { icon: 'fa-calendar',    label: 'Member Since', value: formatDate(p.created_at) },
    { icon: 'fa-clock',       label: 'Last Login',   value: formatDateTime(p.last_login) },
  ];

  document.getElementById('info-grid').innerHTML = fields.map(f => `
    <div class="info-row">
      <span class="info-label"><i class="fas ${esc(f.icon)}"></i>${esc(f.label)}</span>
      <span class="info-value ${f.mono ? 'mono' : ''}"
        ${f.statusColor ? `style="color:${getStatusColor(f.statusColor)}"` : ''}>
        ${esc(String(f.value))}
      </span>
    </div>
  `).join('');
}

/* ─────────────────────────────────────────────
   RENDER: SECURITY (Section 2)
───────────────────────────────────────────── */
function renderSecurity(p) {
  const twoFa = p.two_factor_enabled === true || p.two_factor_enabled === 'true' || p.two_factor_enabled === 1;
  const pwStatus   = p.password_status || 'Unknown';
  const lastChange = formatDateTime(p.last_password_change) || 'Never';

  // Dynamic security score
  let score = 40;
  if (twoFa) score += 40;
  if (p.last_password_change) score += 20;

  const badge = document.getElementById('security-score-badge');
  if (score >= 80) {
    badge.className = 'badge badge-green';
    badge.innerHTML = `<i class="fas fa-star"></i> Strong — ${score}/100`;
  } else if (score >= 50) {
    badge.className = 'badge badge-amber';
    badge.innerHTML = `<i class="fas fa-exclamation"></i> Fair — ${score}/100`;
  } else {
    badge.className = 'badge badge-red';
    badge.innerHTML = `<i class="fas fa-triangle-exclamation"></i> Weak — ${score}/100`;
  }

  document.getElementById('security-body').innerHTML = `
    <div class="security-item">
      <div class="security-left">
        <div class="security-ico card-icon cyan"><i class="fas fa-key"></i></div>
        <div>
          <div class="security-name">Password</div>
          <div class="security-sub">Status: ${esc(pwStatus)} &nbsp;·&nbsp; Changed: ${esc(lastChange)}</div>
        </div>
      </div>
      <button class="btn btn-outline btn-sm" onclick="openModal('modal-password')">
        <i class="fas fa-lock-open"></i> Change Password
      </button>
    </div>

    <div class="security-item">
      <div class="security-left">
        <div class="security-ico card-icon ${twoFa ? 'green' : 'amber'}">
          <i class="fas fa-${twoFa ? 'mobile-screen-button' : 'mobile'}"></i>
        </div>
        <div>
          <div class="security-name">Two-Factor Authentication</div>
          <div class="security-sub">
            ${twoFa
              ? '<span style="color:var(--green)"><i class="fas fa-check-circle"></i> Enabled — TOTP authenticator</span>'
              : '<span style="color:var(--amber)"><i class="fas fa-exclamation-circle"></i> Disabled — Account at risk</span>'}
          </div>
        </div>
      </div>
      <button class="btn ${twoFa ? 'btn-red-soft' : 'btn-green'} btn-sm" id="btn-2fa"
        onclick="toggle2FA(${twoFa})">
        <i class="fas fa-${twoFa ? 'times' : 'plus'}"></i>
        ${twoFa ? 'Disable 2FA' : 'Enable 2FA'}
      </button>
    </div>

    <div class="security-item">
      <div class="security-left">
        <div class="security-ico card-icon purple"><i class="fas fa-clock-rotate-left"></i></div>
        <div>
          <div class="security-name">Last Login</div>
          <div class="security-sub">${esc(formatDateTime(p.last_login) || 'Unknown')}</div>
        </div>
      </div>
      <span class="badge badge-cyan">
        <i class="fas fa-map-marker-alt"></i> ${esc(p.last_login_location || 'Unknown')}
      </span>
    </div>
  `;
}

/* ─────────────────────────────────────────────
   RENDER: ACTIVITY STATS (Section 3)
───────────────────────────────────────────── */
function renderActivity(a) {
  const stats = [
    { key: 'alerts_reviewed',        label: 'Alerts Reviewed',          icon: 'fa-bell',             color: 'purple', val: a.alerts_reviewed },
    { key: 'incidents_resolved',     label: 'Incidents Resolved',       icon: 'fa-circle-check',     color: 'cyan',   val: a.incidents_resolved },
    { key: 'investigations_created', label: 'Investigations Created',   icon: 'fa-magnifying-glass', color: 'green',  val: a.investigations_created },
    { key: 'threat_reports',         label: 'Threat Reports Generated', icon: 'fa-file-shield',      color: 'amber',  val: a.threat_reports_generated || a.threat_reports },
  ];

  const colorMap = {
    purple: { bg: 'var(--purple-dim)', color: 'var(--purple-light)', border: 'rgba(124,58,237,0.2)', val: 'var(--purple-light)' },
    cyan:   { bg: 'var(--cyan-dim)',   color: 'var(--cyan)',          border: 'rgba(34,211,238,0.2)', val: 'var(--cyan)' },
    green:  { bg: 'var(--green-dim)',  color: 'var(--green)',         border: 'rgba(16,185,129,0.2)', val: 'var(--green)' },
    amber:  { bg: 'var(--amber-dim)',  color: 'var(--amber)',         border: 'rgba(245,158,11,0.2)', val: 'var(--amber)' },
  };

  document.getElementById('activity-grid').innerHTML = stats.map((s, i) => {
    const c = colorMap[s.color];
    return `
      <div class="card stat-card ${s.color}-stat" style="animation-delay:${i * 0.08}s">
        <div class="stat-card-icon" style="background:${c.bg};border:1px solid ${c.border}">
          <i class="fas ${esc(s.icon)}" style="color:${c.color}"></i>
        </div>
        <div class="stat-value" id="counter-${s.key}" style="color:${c.val}">0</div>
        <div class="stat-label">${esc(s.label)}</div>
      </div>
    `;
  }).join('');

  // Animate counters after DOM insert
  requestAnimationFrame(() => {
    stats.forEach(s => animateCounter(`counter-${s.key}`, Number(s.val) || 0));
  });
}

/* ─────────────────────────────────────────────
   RENDER: SESSIONS TABLE (Section 4)
───────────────────────────────────────────── */
function renderSessions(sessions) {
  document.getElementById('session-count').textContent =
    `${sessions.length} session${sessions.length !== 1 ? 's' : ''} detected`;

  if (!sessions.length) {
    document.getElementById('sessions-tbody').innerHTML = `
      <tr><td colspan="6" style="text-align:center;padding:2rem;color:var(--text-dim)">
        <i class="fas fa-ghost" style="font-size:1.5rem;display:block;margin-bottom:0.5rem;opacity:0.4"></i>
        No active sessions found
      </td></tr>`;
    return;
  }

  const deviceIcon = (d = '') => {
    const dl = d.toLowerCase();
    if (dl.includes('mobile') || dl.includes('iphone') || dl.includes('android')) return 'fa-mobile-screen';
    if (dl.includes('tablet') || dl.includes('ipad'))                              return 'fa-tablet';
    if (dl.includes('mac') || dl.includes('windows') || dl.includes('linux'))     return 'fa-laptop';
    return 'fa-desktop';
  };

  document.getElementById('sessions-tbody').innerHTML = sessions.map((s, i) => {
    const isCurrent = s.is_current === true || s.current === true;
    return `
      <tr>
        <td>
          <div class="td-device">
            <div class="device-icon"><i class="fas ${deviceIcon(s.device || s.user_agent || '')}"></i></div>
            <span>${esc(s.device || s.browser || 'Unknown Device')}</span>
          </div>
        </td>
        <td class="td-ip">${esc(s.ip_address || s.ip || '—')}</td>
        <td>
          <span style="display:flex;align-items:center;gap:0.4rem;font-size:0.82rem">
            <i class="fas fa-location-dot" style="color:var(--text-dim);font-size:0.7rem"></i>
            ${esc(s.location || '—')}
          </span>
        </td>
        <td style="font-family:var(--font-mono);font-size:0.76rem;color:var(--text-sec)">
          ${esc(formatDateTime(s.login_time || s.created_at) || '—')}
        </td>
        <td>
          ${isCurrent
            ? `<span class="session-current"><i class="fas fa-circle" style="font-size:0.45rem"></i> Current</span>`
            : `<span class="badge badge-purple">Active</span>`}
        </td>
        <td>
          ${isCurrent
            ? `<span style="font-size:0.72rem;color:var(--text-dim);font-style:italic">This session</span>`
            : `<button class="btn btn-red-soft"
                 onclick="revokeSession('${esc(String(s.session_id || s.id || i))}')">
                 <i class="fas fa-sign-out-alt"></i> Revoke
               </button>`}
        </td>
      </tr>
    `;
  }).join('');
}

function renderSessionsError(msg) {
  document.getElementById('sessions-tbody').innerHTML = `
    <tr><td colspan="6" style="text-align:center;padding:1.5rem;color:var(--red)">
      <i class="fas fa-exclamation-triangle" style="margin-right:0.4rem"></i>${esc(msg)}
    </td></tr>`;
}

/* ─────────────────────────────────────────────
   RENDER: ERROR FALLBACK
───────────────────────────────────────────── */
function renderError(containerId, title, detail) {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = `
    <div class="card error-card">
      <div class="error-icon"><i class="fas fa-triangle-exclamation"></i></div>
      <div class="error-title">${esc(title)}</div>
      <div class="error-msg">${esc(detail || 'An unexpected error occurred.')}</div>
      <button class="btn btn-outline" style="margin-top:1rem" onclick="init()">
        <i class="fas fa-rotate-right"></i> Retry
      </button>
    </div>
  `;
}

/* ─────────────────────────────────────────────
   ACTION: EDIT PROFILE
───────────────────────────────────────────── */
function openEditModal() {
  if (!state.profile) return;
  const p = state.profile;
  document.getElementById('edit-fullname').value = p.full_name   || '';
  document.getElementById('edit-email').value    = p.email       || '';
  document.getElementById('edit-dept').value     = p.department  || '';
  document.getElementById('edit-role').value     = p.role        || '';
  openModal('modal-edit');
}

async function saveProfile() {
  const btn  = document.getElementById('btn-save-profile');
  const body = {
    full_name:  document.getElementById('edit-fullname').value.trim(),
    email:      document.getElementById('edit-email').value.trim(),
    department: document.getElementById('edit-dept').value.trim(),
  };

  if (!body.full_name || !body.email) { toast('Name and email are required', 'error'); return; }

  setLoading(btn, true);
  try {
    await apiFetch(CONFIG.endpoints.update, { method: 'PUT', body: JSON.stringify(body) });
    state.profile = { ...state.profile, ...body };
    renderProfile(state.profile);
    closeModal('modal-edit');
    toast('Profile updated successfully', 'success');
  } catch (err) {
    toast(err.message || 'Update failed', 'error');
  } finally {
    setLoading(btn, false);
  }
}

/* ─────────────────────────────────────────────
   ACTION: CHANGE PASSWORD
───────────────────────────────────────────── */
async function changePassword() {
  const current = document.getElementById('pw-current').value;
  const newPw   = document.getElementById('pw-new').value;
  const confirm = document.getElementById('pw-confirm').value;

  if (!current || !newPw || !confirm) { toast('All fields are required', 'error'); return; }
  if (newPw.length < 12)              { toast('Minimum 12 characters required', 'error'); return; }
  if (newPw !== confirm)              { toast('New passwords do not match', 'error'); return; }

  const btn = document.getElementById('btn-change-pw');
  setLoading(btn, true);
  try {
    await apiFetch(CONFIG.endpoints.changePassword, {
      method: 'POST',
      body: JSON.stringify({ current_password: current, new_password: newPw }),
    });
    ['pw-current', 'pw-new', 'pw-confirm'].forEach(id => {
      document.getElementById(id).value = '';
    });
    closeModal('modal-password');
    toast('Password changed successfully', 'success');
    await fetchProfile(); // Refresh security section
  } catch (err) {
    toast(err.message || 'Password change failed', 'error');
  } finally {
    setLoading(btn, false);
  }
}

/* ─────────────────────────────────────────────
   ACTION: TOGGLE 2FA
───────────────────────────────────────────── */
async function toggle2FA(currentlyEnabled) {
  const btn = document.getElementById('btn-2fa');
  if (!btn) return;
  setLoading(btn, true);
  try {
    await apiFetch(CONFIG.endpoints.toggle2fa, {
      method: 'POST',
      body: JSON.stringify({ enable: !currentlyEnabled }),
    });
    state.profile.two_factor_enabled = !currentlyEnabled;
    renderSecurity(state.profile);
    toast(
      currentlyEnabled
        ? 'Two-factor authentication disabled'
        : '2FA enabled — your account is now more secure',
      currentlyEnabled ? 'info' : 'success'
    );
  } catch (err) {
    toast(err.message || '2FA toggle failed', 'error');
    setLoading(btn, false);
  }
}

/* ─────────────────────────────────────────────
   ACTION: REVOKE SESSIONS
───────────────────────────────────────────── */
async function revokeSession(sessionId) {
  try {
    await apiFetch(CONFIG.endpoints.logoutSession, {
      method: 'POST',
      body: JSON.stringify({ session_id: sessionId }),
    });
    toast('Session revoked', 'success');
    await fetchSessions();
  } catch (err) {
    toast(err.message || 'Failed to revoke session', 'error');
  }
}

async function revokeAllSessions() {
  const others = state.sessions.filter(s => !s.is_current && !s.current);
  if (!others.length) { toast('No other sessions to revoke', 'info'); return; }
  if (!confirm(`Revoke ${others.length} other session(s)?`)) return;

  try {
    await Promise.all(others.map(s =>
      apiFetch(CONFIG.endpoints.logoutSession, {
        method: 'POST',
        body: JSON.stringify({ session_id: s.session_id || s.id }),
      })
    ));
    toast(`${others.length} session(s) revoked`, 'success');
    await fetchSessions();
  } catch (err) {
    toast(err.message || 'Failed to revoke sessions', 'error');
  }
}

/* ─────────────────────────────────────────────
   ACTION: COPY USER ID
───────────────────────────────────────────── */
function copyUserId() {
  const id = state.profile?.user_id || state.profile?.id;
  if (!id) return;
  navigator.clipboard.writeText(String(id))
    .then(() => toast('User ID copied to clipboard', 'info'))
    .catch(()  => toast('Could not copy to clipboard', 'error'));
}

/* ─────────────────────────────────────────────
   ACTION: LOGOUT
───────────────────────────────────────────── */
async function handleLogout() {
  try {
    await apiFetch(CONFIG.endpoints.logout, { method: 'POST' });
  } catch { /* ignore */ }
  localStorage.removeItem(CONFIG.sessionKey);
  localStorage.removeItem(CONFIG.userKey);
  window.location.href = '/login';
}

/* ─────────────────────────────────────────────
   MODAL HELPERS
───────────────────────────────────────────── */
function openModal(id) {
  document.getElementById(id).classList.add('open');
  document.body.style.overflow = 'hidden';
}

function closeModal(id) {
  document.getElementById(id).classList.remove('open');
  document.body.style.overflow = '';
}

// Backdrop click closes modal
document.addEventListener('click', e => {
  if (e.target.classList.contains('modal-overlay')) {
    closeModal(e.target.id);
  }
});

// Escape key closes modal
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal-overlay.open').forEach(m => closeModal(m.id));
  }
});

/* ─────────────────────────────────────────────
   UI HELPERS
───────────────────────────────────────────── */
function setLoading(btn, loading) {
  btn.classList.toggle('loading', loading);
  btn.disabled = loading;
}

function toast(message, type = 'info') {
  const icons = { success: 'fa-circle-check', error: 'fa-circle-xmark', info: 'fa-circle-info' };
  const t = document.createElement('div');
  t.className = `toast toast-${type}`;
  t.innerHTML = `<i class="fas ${icons[type] || icons.info} toast-icon"></i><span>${esc(message)}</span>`;
  document.getElementById('toast-container').appendChild(t);
  setTimeout(() => {
    t.style.animation = 'toastOut 0.3s ease forwards';
    setTimeout(() => t.remove(), 320);
  }, 4000);
}

function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function getInitials(name = '') {
  return name.trim().split(/\s+/).map(w => w[0]).slice(0, 2).join('').toUpperCase() || '??';
}

function getStatusColor(status = '') {
  switch (status.toLowerCase()) {
    case 'active':    return 'var(--green)';
    case 'inactive':  return 'var(--red)';
    case 'suspended': return 'var(--amber)';
    default:          return 'var(--text-sec)';
  }
}

function formatDate(str) {
  if (!str) return '—';
  try { return new Date(str).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }); }
  catch { return str; }
}

function formatDateTime(str) {
  if (!str) return '—';
  try { return new Date(str).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' }); }
  catch { return str; }
}

function animateCounter(id, target, duration = 1200) {
  const el = document.getElementById(id);
  if (!el) return;
  if (target === 0) { el.textContent = '0'; return; }
  const start = performance.now();
  const update = now => {
    const progress = Math.min((now - start) / duration, 1);
    const ease = 1 - Math.pow(1 - progress, 3); // ease-out cubic
    el.textContent = Math.round(ease * target).toLocaleString();
    if (progress < 1) requestAnimationFrame(update);
  };
  requestAnimationFrame(update);
}

/* ─────────────────────────────────────────────
   INIT
───────────────────────────────────────────── */
async function init() {
  // Auth guard — hide page if no token
  if (!getToken()) {
    redirectToLogin('No token found');
    return;
  }

  // Show app container
  document.getElementById('app').style.display = 'block';

  // Fetch all data in parallel
  await Promise.all([
    fetchProfile(),
    fetchActivity(),
    fetchSessions(),
  ]);

  // Hide and remove page loader
  const loader = document.getElementById('page-loader');
  if (loader) {
    loader.classList.add('hidden');
    setTimeout(() => loader.remove(), 500);
  }
}

document.addEventListener('DOMContentLoaded', init);
