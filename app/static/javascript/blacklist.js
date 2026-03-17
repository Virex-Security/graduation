/**
 * Blacklist Management Page JavaScript
 * Admin only - Manage blocked IPs, domains, and user agents
 */

'use strict';

/* ─────────────────────────────────────────────
   CONFIG
───────────────────────────────────────────── */
const CONFIG = {
  endpoints: {
    getBlacklist: '/api/blacklist',
    addBlacklist: '/api/blacklist',
    updateBlacklist: '/api/blacklist/',
    deleteBlacklist: '/api/blacklist/',
  },
  sessionKey: 'cyber_shield_session',
};

/* ─────────────────────────────────────────────
   STATE
───────────────────────────────────────────── */
const state = {
  blacklist: [],
  filteredBlacklist: [],
};

/* ─────────────────────────────────────────────
   AUTH HELPERS
───────────────────────────────────────────── */
function getToken() {
  return localStorage.getItem(CONFIG.sessionKey);
}

function redirectToLogin(reason) {
  console.warn('[Blacklist] Auth redirect:', reason);
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
   LOAD BLACKLIST
───────────────────────────────────────────── */
async function loadBlacklist() {
  try {
    const data = await apiFetch(CONFIG.endpoints.getBlacklist);
    state.blacklist = data.blacklist || [];
    state.filteredBlacklist = state.blacklist;
    renderBlacklist(state.blacklist);
    updateStats(state.blacklist);
  } catch (err) {
    if (err.message !== 'Unauthorized') {
      renderError('Failed to load blacklist: ' + err.message);
    }
  }
}

/* ─────────────────────────────────────────────
   RENDER BLACKLIST TABLE
───────────────────────────────────────────── */
function renderBlacklist(items) {
  const tbody = document.getElementById('blacklist-tbody');
  if (!tbody) return;

  if (!items || items.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align:center;padding:2rem;color:var(--text-dim)">
          <i class="fas fa-ban" style="font-size:2rem;display:block;margin-bottom:0.5rem;opacity:0.4"></i>
          No blacklist entries found
        </td>
      </tr>`;
    return;
  }

  tbody.innerHTML = items.map(item => {
    const typeClass = (item.type || 'ip').toLowerCase().replace(' ', '_');
    const statusClass = (item.status || 'active').toLowerCase();
    const isActive = statusClass === 'active';

    return `
      <tr>
        <td>
          <span class="type-badge ${typeClass}">
            <i class="fas fa-${getTypeIcon(item.type)}"></i>
            ${esc(item.type || 'IP')}
          </span>
        </td>
        <td class="value-cell">${esc(item.value || '—')}</td>
        <td class="reason-cell" title="${esc(item.reason || 'No reason provided')}">
          ${esc(item.reason || 'No reason provided')}
        </td>
        <td style="font-size:0.85rem;color:var(--text-secondary)">
          ${esc(item.added_by || 'System')}
        </td>
        <td style="font-size:0.8rem;color:var(--text-secondary)">
          ${formatDateTime(item.date_added || item.created_at) || '—'}
        </td>
        <td>
          <span class="status-badge ${statusClass}">
            <i class="fas fa-circle"></i>
            ${esc(statusClass.charAt(0).toUpperCase() + statusClass.slice(1))}
          </span>
        </td>
        <td>
          <div class="action-buttons">
            <button class="btn-icon-sm" onclick="openEditModal('${esc(String(item.id))}')" title="Edit">
              <i class="fas fa-edit"></i>
            </button>
            <button class="btn-icon-sm" onclick="toggleStatus('${esc(String(item.id))}')" title="${isActive ? 'Deactivate' : 'Activate'}">
              <i class="fas fa-${isActive ? 'pause' : 'play'}"></i>
            </button>
            <button class="btn-icon-sm danger" onclick="confirmDelete('${esc(String(item.id))}', '${esc(item.value)}')" title="Delete">
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
function updateStats(items) {
  const total = items.length;
  const ips = items.filter(i => (i.type || '').toLowerCase() === 'ip').length;
  const domains = items.filter(i => (i.type || '').toLowerCase() === 'domain').length;
  const agents = items.filter(i => (i.type || '').toLowerCase() === 'user_agent' || (i.type || '').toLowerCase() === 'user agent').length;

  animateCounter('total-blacklisted', total);
  animateCounter('blocked-ips', ips);
  animateCounter('blocked-domains', domains);
  animateCounter('blocked-agents', agents);
}

/* ─────────────────────────────────────────────
   FILTER BLACKLIST
───────────────────────────────────────────── */
function filterBlacklist() {
  const searchTerm = document.getElementById('search-blacklist')?.value.toLowerCase() || '';
  const typeFilter = document.getElementById('type-filter')?.value.toLowerCase() || '';
  const statusFilter = document.getElementById('status-filter')?.value.toLowerCase() || '';

  state.filteredBlacklist = state.blacklist.filter(item => {
    const matchesSearch = !searchTerm || 
      (item.value || '').toLowerCase().includes(searchTerm) ||
      (item.reason || '').toLowerCase().includes(searchTerm) ||
      (item.added_by || '').toLowerCase().includes(searchTerm);

    const matchesType = !typeFilter || (item.type || '').toLowerCase().replace(' ', '_') === typeFilter;
    const matchesStatus = !statusFilter || (item.status || '').toLowerCase() === statusFilter;

    return matchesSearch && matchesType && matchesStatus;
  });

  renderBlacklist(state.filteredBlacklist);
}

/* ─────────────────────────────────────────────
   ADD TO BLACKLIST
───────────────────────────────────────────── */
function openAddBlacklistModal() {
  document.getElementById('new-type').value = 'ip';
  document.getElementById('new-value').value = '';
  document.getElementById('new-reason').value = '';
  document.getElementById('new-active').checked = true;
  updatePlaceholder();
  openModal('add-blacklist-modal');
}

function updatePlaceholder() {
  const type = document.getElementById('new-type').value;
  const input = document.getElementById('new-value');
  
  const placeholders = {
    'ip': 'Enter IP address (e.g., 192.168.1.1)',
    'domain': 'Enter domain (e.g., malicious-site.com)',
    'user_agent': 'Enter user agent string'
  };
  
  input.placeholder = placeholders[type] || 'Enter value';
}

async function addToBlacklist() {
  const type = document.getElementById('new-type').value;
  const value = document.getElementById('new-value').value.trim();
  const reason = document.getElementById('new-reason').value.trim();
  const active = document.getElementById('new-active').checked;

  if (!value) {
    toast('Value is required', 'error');
    return;
  }

  if (!reason) {
    toast('Reason is required', 'error');
    return;
  }

  try {
    await apiFetch(CONFIG.endpoints.addBlacklist, {
      method: 'POST',
      body: JSON.stringify({
        type,
        value,
        reason,
        status: active ? 'active' : 'inactive'
      }),
    });
    toast('Added to blacklist successfully', 'success');
    closeModal('add-blacklist-modal');
    await loadBlacklist();
  } catch (err) {
    toast(err.message || 'Failed to add to blacklist', 'error');
  }
}

/* ─────────────────────────────────────────────
   EDIT BLACKLIST
───────────────────────────────────────────── */
function openEditModal(id) {
  const item = state.blacklist.find(i => String(i.id) === String(id));
  if (!item) return;

  document.getElementById('edit-id').value = item.id;
  document.getElementById('edit-type').value = item.type || 'IP';
  document.getElementById('edit-value').value = item.value || '';
  document.getElementById('edit-reason').value = item.reason || '';
  document.getElementById('edit-active').checked = (item.status || 'active').toLowerCase() === 'active';
  
  openModal('edit-blacklist-modal');
}

async function updateBlacklist() {
  const id = document.getElementById('edit-id').value;
  const reason = document.getElementById('edit-reason').value.trim();
  const active = document.getElementById('edit-active').checked;

  if (!reason) {
    toast('Reason is required', 'error');
    return;
  }

  try {
    await apiFetch(CONFIG.endpoints.updateBlacklist + id, {
      method: 'PUT',
      body: JSON.stringify({
        reason,
        status: active ? 'active' : 'inactive'
      }),
    });
    toast('Blacklist entry updated successfully', 'success');
    closeModal('edit-blacklist-modal');
    await loadBlacklist();
  } catch (err) {
    toast(err.message || 'Failed to update blacklist entry', 'error');
  }
}

/* ─────────────────────────────────────────────
   TOGGLE STATUS
───────────────────────────────────────────── */
async function toggleStatus(id) {
  try {
    const item = state.blacklist.find(i => String(i.id) === String(id));
    if (!item) return;

    const newStatus = (item.status || 'active').toLowerCase() === 'active' ? 'inactive' : 'active';
    
    await apiFetch(CONFIG.endpoints.updateBlacklist + id, {
      method: 'PUT',
      body: JSON.stringify({ status: newStatus }),
    });
    toast(`Status changed to ${newStatus}`, 'success');
    await loadBlacklist();
  } catch (err) {
    toast(err.message || 'Failed to toggle status', 'error');
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
   DELETE BLACKLIST ENTRY
───────────────────────────────────────────── */
function confirmDelete(id, value) {
  showConfirm(
    'حذف من القائمة السوداء',
    `هل أنت متأكد من حذف "${value}" من القائمة السوداء؟`,
    () => deleteBlacklist(id)
  );
}

async function deleteBlacklist(id) {
  try {
    await apiFetch(CONFIG.endpoints.deleteBlacklist + id, { method: 'DELETE' });
    toast('Blacklist entry deleted successfully', 'success');
    await loadBlacklist();
  } catch (err) {
    toast(err.message || 'Failed to delete blacklist entry', 'error');
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
  const tbody = document.getElementById('blacklist-tbody');
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

function getTypeIcon(type = '') {
  switch (type.toLowerCase().replace(' ', '_')) {
    case 'ip': return 'network-wired';
    case 'domain': return 'globe';
    case 'user_agent': return 'robot';
    default: return 'ban';
  }
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

  await loadBlacklist();
  
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
