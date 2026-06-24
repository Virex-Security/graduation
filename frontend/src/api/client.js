/**
 * Virex API Client — cookie-based authentication.
 *
 * All requests include credentials: 'include' so the browser
 * automatically sends the httpOnly auth_token cookie.
 * No tokens are ever read or stored in JavaScript.
 */

const BASE = '/api';
const TIMEOUT_MS = 12_000;

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

  const fetchPromise = fetch(`${BASE}${path}`, {
    method,
    headers,
    credentials: 'include',   // ← send httpOnly cookie automatically
    body: body ? JSON.stringify(body) : undefined,
  });

  const res = await withTimeout(fetchPromise, TIMEOUT_MS);

  if (res.status === 401) {
    // Session expired or invalid — redirect to login
    if (!window.location.pathname.includes('/login')) {
      window.location.href = '/login';
    }
    throw new Error('Unauthorized');
  }

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw new Error(data.message || data.error || `HTTP ${res.status}`);
  }

  return data;
}

const API = {
  get:    (path, opts)       => request('GET',    path, null, opts),
  post:   (path, body, opts) => request('POST',   path, body, opts),
  put:    (path, body, opts) => request('PUT',    path, body, opts),
  delete: (path, opts)       => request('DELETE', path, null, opts),
};

export default API;
