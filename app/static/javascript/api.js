/**
 * Centralized API client wrapper for Virex Dashboard
 * Automatically handles 401s, timeouts, and JSON parsing
 */
const API = {
  /**
   * Performs an API fetch and handles common error scenarios
   * Includes automatic CSRF injection and Token Rotation for 401s
   */
  async request(endpoint, options = {}) {
    try {
      const headers = {
        'Accept': 'application/json',
        ...options.headers
      };

      const method = (options.method || 'GET').toUpperCase();
      const safeMethods = ['GET', 'HEAD', 'OPTIONS', 'TRACE'];

      if (!safeMethods.includes(method)) {
          const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
          if (csrfToken && !headers['X-CSRF-Token']) {
              headers['X-CSRF-Token'] = csrfToken;
          }
      }

      if (options.body && !(options.body instanceof FormData)) {
        headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify(options.body);
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), options.timeout || 15000);

      const response = await fetch(endpoint, {
        ...options,
        headers,
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      // 1. Handle Token Rotation on 401 (Seamless refresh)
      if (response.status === 401 && !options._isRetry) {
          const pathName = typeof endpoint === 'string' ? endpoint : (endpoint.url || '');
          if (!pathName.includes('/api/auth/refresh') && !pathName.includes('/login')) {
              try {
                  const refreshResp = await fetch('/api/auth/refresh', {
                      method: 'POST',
                      headers: { 'Accept': 'application/json' }
                  });
                  
                  if (refreshResp.ok) {
                      // Retry original request
                      return this.request(endpoint, { ...options, _isRetry: true });
                  } else {
                      window.location.href = '/login?error=Session+Expired';
                      throw new Error('Session Expired');
                  }
              } catch (e) {
                  window.location.href = '/login';
                  throw e;
              }
          }
      }

      // 2. Handle other auth failures
      if (response.status === 403) {
        window.location.href = '/login?msg=Permission+denied';
        throw new Error('Permission denied');
      }

      const data = await response.json().catch(() => null);

      if (!response.ok) {
        const errorMsg = data?.error || data?.message || `HTTP ${response.status} failed`;
        throw new Error(errorMsg);
      }

      return data;

    } catch (error) {
      if (error.name === 'AbortError') throw new Error('Request timed out');
      throw error;
    }
  },

  get(endpoint, options = {}) {
    return this.request(endpoint, { ...options, method: 'GET' });
  },

  post(endpoint, body, options = {}) {
    return this.request(endpoint, { ...options, method: 'POST', body });
  },

  put(endpoint, body, options = {}) {
    return this.request(endpoint, { ...options, method: 'PUT', body });
  },

  delete(endpoint, options = {}) {
    return this.request(endpoint, { ...options, method: 'DELETE' });
  }
};

window.API = API;
