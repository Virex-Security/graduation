/**
 * Central API client for Virex Dashboard.
 * Wraps fetch with auth, error handling, and timeout logic.
 */

const BASE = '/api';
const TIMEOUT_MS = 12000;

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Request timed out')), ms)
    ),
  ]);
}

async function request(method, path, body = null, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...opts.headers };
  const token = localStorage.getItem('virex_token');
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const fetchPromise = fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  const res = await withTimeout(fetchPromise, TIMEOUT_MS);

  if (res.status === 401) {
    localStorage.removeItem('virex_token');
    window.location.href = '/login';
    throw new Error('Unauthorized');
  }

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw new Error(data.message || data.error || `HTTP ${res.status}`);
  }

  return data;
}

const API = {
  get: (path, opts) => request('GET', path, null, opts),
  post: (path, body, opts) => request('POST', path, body, opts),
  put: (path, body, opts) => request('PUT', path, body, opts),
  delete: (path, opts) => request('DELETE', path, null, opts),
};

export default API;
