/**
 * User Manager Page JavaScript
 * Handles user management operations for admins
 */

'use strict';

/* ─────────────────────────────────────────────
   CONFIG
───────────────────────────────────────────── */
const CONFIG = {
  endpoints: {
    getUsers: '/api/users',
    getUserDetails: '/api/users/',
    toggleStatus: '/api/users/{id}/toggle-status',
    changeRole: '/api/users/{id}/change-role',
    deleteUser: '/api/users/{id}',
  },
  sessionKey: 'cyber_shield_session',
};

/* ─────────────────────────────────────────────
   STATE
───────────────────────────────────────────── */
const state = {
  users: [],
  filteredUsers: [],
  currentUser: null,
};

/* ─────────────────────────────────────────────
   AUTH HELPERS
───────────────────────────────────────────── */
function getToken() {
  return localStorage.getItem(CONFIG.sessionKey);
}

function redirectToLogin(reason) {
  console.warn('[UserManager] Auth redirect:', reason);
  localStorage.removeItem(CONFIG.sessionKey);
  window.location.href = '/login';
}

/* ─────────────────────────────────────────────
   API LAYER
───────────────────────────────────────────── */
async function apiFetch(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
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
   LOAD USERS
───────────────────────────────────────────── */
async function loadUsers() {
  try {
    const data = await apiFetch(CONFIG.endpoints.getUsers);
    state.users = data.users || [];
    state.filteredUsers = state.users;
    renderUsers(state.users);
    updateStats(state.users);
  } catch (err) {
    if (err.message !== 'Unauthorized') {
      renderError('Failed to load users: ' + err.message);
    }
  }
}

/* ─────────────────────────────────────────────
   RENDER USERS TABLE
───────────────────────────────────────────── */
function renderUsers(users) {
  const tbody = document.getElementById('users-tbody');
  if (!tbody) return;

  if (!users || users.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align:center;padding:2rem;color:var(--text-dim)">
          <i class="fas fa-users" style="font-size:2rem;display:block;margin-bottom:0.5rem;opacity:0.4"></i>
          No users found
        </td>
      </tr>`;
    return;
  }

  tbody.innerHTML = users.map(user => {
    const initials = getInitials(user.full_name || user.username || 'U');
    const roleClass = (user.role || 'viewer').toLowerCase();
    const statusClass = (user.status || user.account_status || 'active').toLowerCase();
    const isActive = statusClass === 'active';

    return `
      <tr>
        <td>
          <div class="user-cell">
            <div class="user-avatar">${esc(initials)}</div>
            <div class="user-info">
              <div class="user-name">${esc(user.full_name || user.username || 'Unknown')}</div>
              <div class="user-id">ID: ${esc(user.user_id || user.id || 'N/A')}</div>
            </div>
          </div>
        </td>
        <td>${esc(user.email || '—')}</td>
        <td>
          <span class="role-badge ${roleClass}">
            <i class="fas fa-${getRoleIcon(user.role)}"></i>
            ${esc(user.role || 'Viewer')}
          </span>
        </td>
        <td>
          <span class="status-badge ${statusClass}">
            <i class="fas fa-circle"></i>
            ${esc(statusClass.charAt(0).toUpperCase() + statusClass.slice(1))}
          </span>
        </td>
        <td class="actions-count">${user.total_actions || 0}</td>
        <td style="font-size:0.8rem;color:var(--text-secondary)">
          ${formatDateTime(user.last_action) || '—'}
        </td>
        <td>
          <div class="action-buttons">
            <button class="btn-icon-sm" onclick="viewUserDetails('${esc(String(user.user_id || user.id))}')" title="View Details">
              <i class="fas fa-eye"></i>
            </button>
            <button class="btn-icon-sm" onclick="toggleUserStatus('${esc(String(user.user_id || user.id))}')" title="${isActive ? 'Deactivate' : 'Activate'}">
              <i class="fas fa-${isActive ? 'ban' : 'check'}"></i>
            </button>
            <button class="btn-icon-sm danger" onclick="confirmDeleteUser('${esc(String(user.user_id || user.id))}', '${esc(user.username || 'this user')}')" title="Delete User">
              <i class="fas fa-trash"></i>
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

/* ─────────────────────────────────────────────
   UPDATE STATS
───────────────────────────────────────────── */
function updateStats(users) {
  const total = users.length;
  const active = users.filter(u => (u.status || u.account_status || '').toLowerCase() === 'active').length;
  const admins = users.filter(u => (u.role || '').toLowerCase() === 'admin').length;
  const online = users.filter(u => u.is_online || u.online).length;

  animateCounter('total-users', total);
  animateCounter('active-users', active);
  animateCounter('admin-users', admins);
  animateCounter('online-users', online);
}

/* ─────────────────────────────────────────────
   FILTER USERS
───────────────────────────────────────────── */
function filterUsers() {
  const searchTerm = document.getElementById('search-users')?.value.toLowerCase() || '';
  const roleFilter = document.getElementById('role-filter')?.value.toLowerCase() || '';
  const statusFilter = document.getElementById('status-filter')?.value.toLowerCase() || '';

  state.filteredUsers = state.users.filter(user => {
    const matchesSearch = !searchTerm || 
      (user.username || '').toLowerCase().includes(searchTerm) ||
      (user.full_name || '').toLowerCase().includes(searchTerm) ||
      (user.email || '').toLowerCase().includes(searchTerm);

    const matchesRole = !roleFilter || (user.role || '').toLowerCase() === roleFilter;
    const matchesStatus = !statusFilter || (user.status || user.account_status || '').toLowerCase() === statusFilter;

    return matchesSearch && matchesRole && matchesStatus;
  });

  renderUsers(state.filteredUsers);
}

/* ─────────────────────────────────────────────
   VIEW USER DETAILS
───────────────────────────────────────────── */
async function viewUserDetails(userId) {
  try {
    const data = await apiFetch(CONFIG.endpoints.getUserDetails + userId);
    const user = data.user || data;
    const actions = data.actions || [];

    // Populate modal
    document.getElementById('modal-user-name').textContent = user.full_name || user.username || 'User Details';
    document.getElementById('detail-username').textContent = user.username || '—';
    document.getElementById('detail-email').textContent = user.email || '—';
    document.getElementById('detail-role').textContent = user.role || '—';
    document.getElementById('detail-status').textContent = user.status || user.account_status || '—';
    document.getElementById('detail-created').textContent = formatDate(user.created_at) || '—';
    document.getElementById('detail-last-login').textContent = formatDateTime(user.last_login) || '—';

    // Render actions
    const actionsList = document.getElementById('user-actions-list');
    if (actions.length === 0) {
      actionsList.innerHTML = '<div style="text-align:center;padding:2rem;color:var(--text-dim)">No recent actions</div>';
    } else {
      actionsList.innerHTML = actions.map(action => `
        <div class="action-item">
          <div class="action-header">
            <span class="action-name">${esc(action.action || 'Unknown Action')}</span>
            <span class="action-time">${formatDateTime(action.timestamp) || '—'}</span>
          </div>
          <div class="action-details">${esc(action.details || 'No details available')}</div>
        </div>
      `).join('');
    }

    openModal('user-details-modal');
  } catch (err) {
    toast(err.message || 'Failed to load user details', 'error');
  }
}

/* ─────────────────────────────────────────────
   TOGGLE USER STATUS
───────────────────────────────────────────── */
async function toggleUserStatus(userId) {
  try {
    const url = CONFIG.endpoints.toggleStatus.replace('{id}', userId);
    const data = await apiFetch(url, { method: 'POST' });
    toast(`User status changed to ${data.new_status}`, 'success');
    await loadUsers();
  } catch (err) {
    toast(err.message || 'Failed to toggle user status', 'error');
  }
}

/* ─────────────────────────────────────────────
   ADD USER MODAL
───────────────────────────────────────────── */
function openAddUserModal() {
  document.getElementById('new-username').value = '';
  document.getElementById('new-email').value = '';
  document.getElementById('new-password').value = '';
  document.getElementById('new-role').value = 'viewer';
  openModal('add-user-modal');
}

async function addUser() {
  const username = document.getElementById('new-username').value.trim();
  const email = document.getElementById('new-email').value.trim();
  const password = document.getElementById('new-password').value;
  const role = document.getElementById('new-role').value;

  if (!username || !email || !password) {
    toast('All fields are required', 'error');
    return;
  }

  if (password.length < 8) {
    toast('Password must be at least 8 characters', 'error');
    return;
  }

  try {
    await apiFetch('/api/users', {
      method: 'POST',
      body: JSON.stringify({ username, email, password, role }),
    });
    toast('User created successfully', 'success');
    closeModal('add-user-modal');
    await loadUsers();
  } catch (err) {
    toast(err.message || 'Failed to create user', 'error');
  }
}

/* ─────────────────────────────────────────────
   CUSTOM CONFIRM DIALOG
───────────────────────────────────────────── */
function showConfirm(title, message, onConfirm) {
  // Create overlay
  const overlay = document.createElement('div');
  overlay.className = 'confirm-alert-overlay';
  overlay.id = 'confirm-overlay';
  
  // Create alert
  const alert = document.createElement('div');
  alert.className = 'confirm-alert';
  alert.id = 'confirm-alert';
  alert.innerHTML = `
    <div class="confirm-alert-title">${esc(title)}</div>
    <div class="confirm-alert-message">${esc(message)}</div>
    <div class="confirm-alert-buttons">
      <button class="btn btn-confirm" onclick="closeConfirm(true)">
        <i class="fas fa-check"></i>
      </button>
      <button class="btn btn-cancel" onclick="closeConfirm(false)">
        <i class="fas fa-times"></i>
      </button>
    </div>
  `;
  
  // Add to body
  document.body.appendChild(overlay);
  document.body.appendChild(alert);
  
  // Show with animation
  requestAnimationFrame(() => {
    overlay.classList.add('show');
    alert.classList.add('show');
  });
  
  // Store callback
  window._confirmCallback = onConfirm;
}

function closeConfirm(confirmed) {
  const overlay = document.getElementById('confirm-overlay');
  const alert = document.getElementById('confirm-alert');
  
  if (overlay && alert) {
    overlay.classList.remove('show');
    alert.classList.remove('show');
    setTimeout(() => {
      overlay.remove();
      alert.remove();
    }, 300);
  }
  
  if (confirmed && window._confirmCallback) {
    window._confirmCallback();
  }
  window._confirmCallback = null;
}

/* ─────────────────────────────────────────────
   DELETE USER
───────────────────────────────────────────── */
function confirmDeleteUser(userId, username) {
  showConfirm(
    'حذف المستخدم',
    `هل أنت متأكد من حذف المستخدم "${username}"؟ لا يمكن التراجع عن هذا الإجراء.`,
    () => deleteUser(userId)
  );
}

async function deleteUser(userId) {
  try {
    const url = CONFIG.endpoints.deleteUser.replace('{id}', userId);
    await apiFetch(url, { method: 'DELETE' });
    toast('User deleted successfully', 'success');
    await loadUsers();
  } catch (err) {
    toast(err.message || 'Failed to delete user', 'error');
  }
}

/* ─────────────────────────────────────────────
   MODAL HELPERS
───────────────────────────────────────────── */
function openModal(id) {
  const modal = document.getElementById(id);
  if (modal) {
    modal.classList.add('open');
    document.body.style.overflow = 'hidden';
  }
}

function closeModal(id) {
  const modal = document.getElementById(id);
  if (modal) {
    modal.classList.remove('open');
    document.body.style.overflow = '';
  }
}

// Backdrop click closes modal
document.addEventListener('click', e => {
  if (e.target.classList.contains('modal-overlay') && 
      e.target.id !== 'confirm-overlay' &&
      !e.target.id.includes('confirm')) {
    closeModal(e.target.id);
  }
});

// Escape key closes modal
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    const confirmOverlay = document.getElementById('confirm-overlay');
    const confirmAlert = document.getElementById('confirm-alert');
    
    // Don't close confirm dialogs with Escape
    if (confirmOverlay && confirmOverlay.classList.contains('show')) {
      return;
    }
    
    document.querySelectorAll('.modal-overlay.open').forEach(m => {
      if (m.id !== 'confirm-overlay' && !m.id.includes('confirm')) {
        closeModal(m.id);
      }
    });
  }
});

/* ─────────────────────────────────────────────
   UI HELPERS
───────────────────────────────────────────── */
function toast(message, type = 'info') {
  const icons = { success: 'fa-circle-check', error: 'fa-circle-xmark', info: 'fa-circle-info' };
  const t = document.createElement('div');
  t.className = `toast toast-${type}`;
  t.innerHTML = `<i class="fas ${icons[type] || icons.info} toast-icon"></i><span>${esc(message)}</span>`;
  
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.style.cssText = 'position:fixed;top:1rem;right:1rem;z-index:10000;display:flex;flex-direction:column;gap:0.5rem;';
    document.body.appendChild(container);
  }
  
  container.appendChild(t);
  setTimeout(() => {
    t.style.animation = 'toastOut 0.3s ease forwards';
    setTimeout(() => t.remove(), 320);
  }, 4000);
}

function renderError(message) {
  const tbody = document.getElementById('users-tbody');
  if (tbody) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align:center;padding:2rem;color:var(--red)">
          <i class="fas fa-exclamation-triangle" style="font-size:2rem;display:block;margin-bottom:0.5rem"></i>
          ${esc(message)}
        </td>
      </tr>`;
  }
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

function getRoleIcon(role = '') {
  switch (role.toLowerCase()) {
    case 'admin': return 'user-shield';
    case 'analyst': return 'user-tie';
    case 'viewer': return 'user';
    default: return 'user';
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
    const ease = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(ease * target).toLocaleString();
    if (progress < 1) requestAnimationFrame(update);
  };
  requestAnimationFrame(update);
}

/* ─────────────────────────────────────────────
   INIT
───────────────────────────────────────────── */
async function init() {
  if (!getToken()) {
    redirectToLogin('No token found');
    return;
  }

  await loadUsers();
  
  // Initialize Reset Button
  const sidebarResetBtn = document.getElementById('sidebar-reset-btn');
  if (sidebarResetBtn) {
    sidebarResetBtn.addEventListener('click', function() {
      showConfirm(
        'إعادة تعيين الإحصائيات',
        'هل أنت متأكد من إعادة تعيين جميع الإحصائيات؟ لا يمكن التراجع عن هذا الإجراء.',
        function() {
          fetch('/api/dashboard/reset', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
          })
            .then(response => response.json())
            .then(data => {
              if (data.status === 'stats_reset') {
                toast('تم إعادة تعيين الإحصائيات بنجاح!', 'success');
                setTimeout(() => location.reload(), 1500);
              } else {
                toast('فشل إعادة التعيين', 'error');
              }
            })
            .catch(error => {
              console.error('Reset error:', error);
              toast('فشل في إعادة تعيين الإحصائيات', 'error');
            });
        }
      );
    });
  }
}

document.addEventListener('DOMContentLoaded', init);
