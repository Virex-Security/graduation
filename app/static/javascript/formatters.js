/**
 * Common formatting utilities for Dashboard dates, numbers, and strings
 */

const Formatters = {
  /**
   * Format ISO date strings or timestamps into human readable
   * Returns: "Mar 30, 2026, 21:03"
   */
  formatDate(dateVal) {
    if (!dateVal) return "—";
    const d = new Date(dateVal);
    if (isNaN(d.getTime())) return dateVal;
    
    return d.toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit"
    });
  },

  /**
   * Formats numbers with thousands separator (e.g., 1000 -> 1,000)
   */
  formatNumber(num) {
    if (num === null || num === undefined) return "0";
    return Number(num).toLocaleString('en-US');
  },

  /**
   * Safely formats IP addresses, masking internal IPs if needed
   */
  formatIP(ip) {
    if (!ip) return "—";
    
    // Validate IPv4
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(ip)) {
      return ip;
    }
    
    // Validate IPv6
    const ipv6Regex = /^([\da-f]{1,4}:){7}[\da-f]{1,4}$/i;
    if (ipv6Regex.test(ip)) {
      return ip;
    }

    return "—"; // Mask invalid
  },

  /**
   * Formats percentages securely
   */
  formatPercent(val, decimals = 1) {
    if (val === null || isNaN(val)) return "—%";
    return `${Number(val).toFixed(decimals)}%`;
  },

  /**
   * XSS Protection: Escapes HTML from user strings injected into DOM
   */
  escapeHTML(str) {
    if (!str) return "";
    const div = document.createElement('div');
    div.innerText = str;
    return div.innerHTML;
  },

  /**
   * Truncate long strings carefully
   */
  truncate(str, length = 30) {
    if (!str) return "";
    if (str.length <= length) return str;
    return str.substring(0, length) + "...";
  }
};

window.Formatters = Formatters;
