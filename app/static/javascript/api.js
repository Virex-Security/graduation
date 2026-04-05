/**
 * Centralized API client wrapper for Virex Dashboard
 * Automatically handles 401s, timeouts, and JSON parsing
 */
const API = {
  /**
   * Performs an API fetch and handles common error scenarios
   * @param {string} endpoint 
   * @param {RequestInit} options
   */
  async request(endpoint, options = {}) {
    try {
      // Add standard headers
      const headers = {
        'Accept': 'application/json',
        ...options.headers
      };

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

      // Handle auth failures
      if (response.status === 401) {
        window.location.href = '/login?msg=Session+expired';
        throw new Error('Authentication required');
      }

      const data = await response.json().catch(() => null);

      if (response.status === 403) {
        throw new Error(data?.message || data?.error || 'You do not have permission to perform this action.');
      }

      if (!response.ok) {
        const errorMsg = data?.error || data?.message || `HTTP ${response.status} failed`;
        throw new Error(errorMsg);
      }

      return data;

    } catch (error) {
      if (error.name === 'AbortError') {
        throw new Error('Request timed out. Please check your connection.');
      }
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
