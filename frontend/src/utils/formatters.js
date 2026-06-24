/**
 * Reusable formatting utilities for the Virex dashboard.
 */

/** Format an ISO date string to a human-readable form */
export function formatDate(isoString) {
  if (!isoString) return '—';
  try {
    return new Intl.DateTimeFormat('en-GB', {
      year: 'numeric', month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false,
    }).format(new Date(isoString));
  } catch {
    return isoString;
  }
}

/** Format a relative time from now (e.g. "3 minutes ago") */
export function timeAgo(isoString) {
  if (!isoString) return '—';
  try {
    const diff = Date.now() - new Date(isoString).getTime();
    const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
    const minutes = Math.round(diff / 60000);
    if (Math.abs(minutes) < 60) return rtf.format(-minutes, 'minute');
    const hours = Math.round(minutes / 60);
    if (Math.abs(hours) < 24) return rtf.format(-hours, 'hour');
    return rtf.format(-Math.round(hours / 24), 'day');
  } catch {
    return isoString;
  }
}

/** Validate and format an IP address, returns '—' if invalid */
export function formatIP(ip) {
  if (!ip || typeof ip !== 'string') return '—';
  const trimmed = ip.trim();
  const v4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const v6 = /^[0-9a-fA-F:]+$/;
  return v4.test(trimmed) || v6.test(trimmed) ? trimmed : '—';
}

/** Format a number with thousands separators */
export function formatNumber(n) {
  if (n === null || n === undefined) return '0';
  return new Intl.NumberFormat('en-US').format(Number(n));
}

/** Return a Tailwind class for a severity string (design system: severity.*) */
export function severityClass(severity) {
  const s = (severity || '').toLowerCase();
  if (s === 'critical') return 'text-severity-critical bg-severity-critical/10 border-severity-critical/30';
  if (s === 'high') return 'text-severity-high bg-severity-high/10 border-severity-high/30';
  if (s === 'medium') return 'text-severity-medium bg-severity-medium/10 border-severity-medium/30';
  if (s === 'low') return 'text-severity-low bg-severity-low/10 border-severity-low/30';
  return 'text-severity-unknown bg-severity-unknown/10 border-severity-unknown/30';
}

/** Return a Tailwind class for a status string */
export function statusClass(status) {
  const s = (status || '').toLowerCase();
  if (s === 'resolved' || s === 'closed') return 'text-success bg-success/10 border-success/30';
  if (s === 'open' || s === 'new') return 'text-danger bg-danger/10 border-danger/30';
  if (s === 'investigating') return 'text-warning bg-warning/10 border-warning/30';
  return 'text-text-muted bg-text-muted/10 border-text-muted/30';
}

/** Sanitize string to prevent XSS in dangerouslySetInnerHTML */
export function sanitize(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/** Truncate a long string with ellipsis */
export function truncate(str, max = 60) {
  if (!str) return '';
  return str.length > max ? str.slice(0, max) + '…' : str;
}
