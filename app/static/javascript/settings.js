/**
 * Settings Page JavaScript
 * Handles loading and saving system settings
 */

'use strict';

/* ─────────────────────────────────────────────
   CONFIG
───────────────────────────────────────────── */
const CONFIG = {
  endpoints: {
    getSettings: '/api/settings',
    updateSettings: '/api/settings',
  },
  sessionKey: 'cyber_shield_session',
};

/* ─────────────────────────────────────────────
   STATE
───────────────────────────────────────────── */
const state = {
  settings: null,
  profile: null,
  hasChanges: false,
};

/* ─────────────────────────────────────────────
   AUTH HELPERS
───────────────────────────────────────────── */
function getToken() {
  return localStorage.getItem(CONFIG.sessionKey);
}

function redirectToLogin(reason) {
  console.warn('[Settings] Auth redirect:', reason);
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
   LOAD SETTINGS & PROFILE
───────────────────────────────────────────── */
async function loadSettings() {
  try {
    const data = await apiFetch(CONFIG.endpoints.getSettings);
    state.settings = data;
    populateSettings(data);
  } catch (err) {
    if (err.message !== 'Unauthorized') {
      toast('Failed to load settings: ' + err.message, 'error');
    }
  }
}

async function loadProfile() {
  try {
    const data = await apiFetch('/api/profile');
    const user = data.user || data;
    
    // Update profile display
    const avatar = document.getElementById('profile-avatar');
    if (user.avatar_url) {
      avatar.style.backgroundImage = `url(${user.avatar_url})`;
      avatar.style.backgroundSize = 'cover';
      avatar.textContent = '';
    } else {
      avatar.textContent = getInitials(user.full_name || user.username || 'U');
    }
    
    document.getElementById('profile-name').textContent = user.full_name || user.username || '—';
    document.getElementById('profile-role').textContent = user.role || '—';
    document.getElementById('profile-email').textContent = user.email || '—';
    document.getElementById('profile-department').textContent = user.department || '—';
    document.getElementById('profile-created').textContent = formatDate(user.created_at) || '—';
    document.getElementById('profile-last-login').textContent = formatDateTime(user.last_login) || '—';
    
    // Store for editing
    state.profile = user;
  } catch (err) {
    if (err.message !== 'Unauthorized') {
      console.error('Failed to load profile:', err);
    }
  }
}

/* ─────────────────────────────────────────────
   POPULATE FORM
───────────────────────────────────────────── */
function populateSettings(settings) {
  // General Settings
  if (settings.general) {
    setValue('site-name', settings.general.site_name);
    setValue('timezone', settings.general.timezone);
    setValue('language', settings.general.language);
    setValue('date-format', settings.general.date_format);
  }

  // Security Settings
  if (settings.security) {
    setValue('session-timeout', settings.security.session_timeout);
    setValue('max-login-attempts', settings.security.max_login_attempts);
    setValue('password-expiry', settings.security.password_expiry_days);
    setChecked('require-2fa', settings.security.require_2fa);
  }

  // Notifications
  if (settings.notifications) {
    setChecked('email-alerts', settings.notifications.email_alerts);
    setChecked('slack-integration', settings.notifications.slack_integration);
    setValue('alert-threshold', settings.notifications.alert_threshold);
  }

  // ML Model
  if (settings.ml_model) {
    setChecked('auto-retrain', settings.ml_model.auto_retrain);
    setValue('confidence-threshold', settings.ml_model.confidence_threshold);
    setValue('model-version', settings.ml_model.model_version);
  }

  // API
  if (settings.api) {
    setValue('rate-limit', settings.api.rate_limit);
    setValue('api-key-expiry', settings.api.api_key_expiry_days);
    setChecked('cors-enabled', settings.api.cors_enabled);
  }
}

/* ─────────────────────────────────────────────
   EDIT PROFILE
───────────────────────────────────────────── */
function openEditProfileModal() {
  if (!state.profile) return;
  
  document.getElementById('edit-fullname').value = state.profile.full_name || '';
  document.getElementById('edit-email').value = state.profile.email || '';
  
  // Handle department dropdown selection
  const deptSelect = document.getElementById('edit-department');
  if (deptSelect && state.profile.department) {
    // Try to find exact match first
    let optionFound = false;
    for (let option of deptSelect.options) {
      if (option.value === state.profile.department) {
        option.selected = true;
        optionFound = true;
        break;
      }
    }
    
    // If no exact match, try to set to "Other"
    if (!optionFound) {
      for (let option of deptSelect.options) {
        if (option.value === 'Other') {
          option.selected = true;
          break;
        }
      }
    }
  }
  
  document.getElementById('edit-password').value = '';
  
  openModal('edit-profile-modal');
}

async function saveProfile() {
  console.log('Save Profile button clicked'); // Debug log
  
  const fullname = document.getElementById('edit-fullname').value.trim();
  const email = document.getElementById('edit-email').value.trim();
  const deptSelect = document.getElementById('edit-department');
  const department = deptSelect ? deptSelect.value.trim() : '';
  const password = document.getElementById('edit-password').value;
  
  console.log('Form data:', { fullname, email, department, password: password ? '[HIDDEN]' : '' }); // Debug log
  
  if (!fullname || !email) {
    toast('Name and email are required', 'error');
    return;
  }
  
  if (!department) {
    toast('Department is required', 'error');
    return;
  }
  
  const body = {
    full_name: fullname,
    email: email,
    department: department,
  };
  
  if (password) {
    body.password = password;
  }
  
  console.log('Sending API request with body:', body); // Debug log
  
  try {
    const response = await apiFetch('/api/profile/update', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    
    console.log('API response:', response); // Debug log
    
    toast('Profile updated successfully', 'success');
    closeModal('edit-profile-modal');
    await loadProfile();
  } catch (err) {
    console.error('API error:', err); // Debug log
    toast(err.message || 'Failed to update profile', 'error');
  }
}

/* ─────────────────────────────────────────────
   SAVE SETTINGS
───────────────────────────────────────────── */
async function saveSettings() {
  const btn = document.getElementById('save-settings-btn');
  if (!btn) return;

  const settings = {
    general: {
      site_name: getValue('site-name'),
      timezone: getValue('timezone'),
      language: getValue('language'),
      date_format: getValue('date-format'),
    },
    security: {
      session_timeout: parseInt(getValue('session-timeout')),
      max_login_attempts: parseInt(getValue('max-login-attempts')),
      password_expiry_days: parseInt(getValue('password-expiry')),
      require_2fa: getChecked('require-2fa'),
    },
    notifications: {
      email_alerts: getChecked('email-alerts'),
      slack_integration: getChecked('slack-integration'),
      alert_threshold: getValue('alert-threshold'),
    },
    ml_model: {
      auto_retrain: getChecked('auto-retrain'),
      confidence_threshold: parseFloat(getValue('confidence-threshold')),
      model_version: getValue('model-version'),
    },
    api: {
      rate_limit: parseInt(getValue('rate-limit')),
      api_key_expiry_days: parseInt(getValue('api-key-expiry')),
      cors_enabled: getChecked('cors-enabled'),
    },
  };

  setLoading(btn, true);
  try {
    await apiFetch(CONFIG.endpoints.updateSettings, {
      method: 'POST',
      body: JSON.stringify(settings),
    });
    state.settings = settings;
    state.hasChanges = false;
    toast('Settings saved successfully', 'success');
  } catch (err) {
    toast(err.message || 'Failed to save settings', 'error');
  } finally {
    setLoading(btn, false);
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
  if (e.target.classList.contains('modal-overlay') && e.target.id !== 'confirm-overlay') {
    closeModal(e.target.id);
  }
});

// Escape key closes modal
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal-overlay.open').forEach(m => {
      if (m.id !== 'confirm-overlay') {
        closeModal(m.id);
      }
    });
  }
});

/* ─────────────────────────────────────────────
   FORM HELPERS
───────────────────────────────────────────── */
function getValue(id) {
  const el = document.getElementById(id);
  return el ? el.value : '';
}

function setValue(id, value) {
  const el = document.getElementById(id);
  if (el) el.value = value || '';
}

function getChecked(id) {
  const el = document.getElementById(id);
  return el ? el.checked : false;
}

function setChecked(id, checked) {
  const el = document.getElementById(id);
  if (el) el.checked = !!checked;
}

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

/* ─────────────────────────────────────────────
   TRACK CHANGES
───────────────────────────────────────────── */
function trackChanges() {
  const inputs = document.querySelectorAll('.setting-input, .setting-select, .toggle-switch input');
  inputs.forEach(input => {
    input.addEventListener('change', () => {
      state.hasChanges = true;
    });
  });
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
   INIT
───────────────────────────────────────────── */
async function init() {
  if (!getToken()) {
    redirectToLogin('No token found');
    return;
  }

  await Promise.all([
    loadProfile(),
    loadSettings()
  ]);
  trackChanges();
  
  // Initialize Save Profile Button
  const saveProfileBtn = document.getElementById('save-profile-btn');
  if (saveProfileBtn) {
    saveProfileBtn.addEventListener('click', function(e) {
      e.preventDefault();
      console.log('Save Profile button clicked via event listener');
      saveProfile();
    });
  }
  
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
