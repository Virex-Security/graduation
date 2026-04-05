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

<<<<<<< HEAD
=======
      // Auto-add CSRF token for state-changing requests
      const method = (options.method || 'GET').toUpperCase();
      if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
        if (csrfToken) {
          headers['X-CSRFToken'] = csrfToken;
        }
      }

>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
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
<<<<<<< HEAD
      if (response.status === 401 || response.status === 403) {
=======
      if (response.status === 401) {
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
        window.location.href = '/login?msg=Session+expired';
        throw new Error('Authentication required');
      }

      const data = await response.json().catch(() => null);

<<<<<<< HEAD
=======
      if (response.status === 403) {
        throw new Error(data?.message || data?.error || 'You do not have permission to perform this action.');
      }

>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
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
