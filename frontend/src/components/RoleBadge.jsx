import { memo } from 'react';

const ROLE_STYLES = {
  admin:
    'border-brand-primary/40 bg-brand-primary/15 text-brand-primary shadow-sm shadow-brand-primary/10',
  analyst: 'border-info/35 bg-info/12 text-info shadow-sm shadow-info/10',
  viewer: 'border-border-dim bg-bg-secondary/90 text-text-secondary shadow-sm',
};

/** Normalize API role string for display */
export function formatRoleLabel(role) {
  const r = (role || '').toLowerCase();
  if (r === 'viewer') return 'User';
  if (r === 'admin') return 'Admin';
  if (r === 'analyst') return 'Analyst';
  if (!role) return '—';
  return role.charAt(0).toUpperCase() + role.slice(1).toLowerCase();
}

function RoleBadge({ role, className = '' }) {
  const r = (role || '').toLowerCase();
  const styles = ROLE_STYLES[r] ?? 'border-severity-unknown/40 bg-severity-unknown/10 text-severity-unknown';

  return (
    <span
      className={`inline-flex items-center rounded-full border px-ds-3 py-ds-1 text-ds-caption font-bold uppercase tracking-ds-wide ${styles} ${className}`}
    >
      {formatRoleLabel(role)}
    </span>
  );
}

export default memo(RoleBadge);
