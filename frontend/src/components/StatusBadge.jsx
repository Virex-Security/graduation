import { memo } from 'react';

const STATUS_STYLES = {
  active: 'border-success/40 bg-success/12 text-success',
  inactive: 'border-border-dim bg-bg-secondary/80 text-text-muted',
  suspended: 'border-severity-critical/40 bg-severity-critical/10 text-severity-critical',
};

export function formatStatusLabel(status) {
  const s = (status || '').toLowerCase();
  if (s === 'active') return 'Active';
  if (s === 'inactive') return 'Inactive';
  if (s === 'suspended') return 'Suspended';
  if (!status) return '—';
  return status.charAt(0).toUpperCase() + status.slice(1).toLowerCase();
}

function StatusBadge({ status, showPulse = true, className = '' }) {
  const s = (status || '').toLowerCase();
  const styles = STATUS_STYLES[s] ?? 'border-severity-unknown/40 bg-severity-unknown/10 text-severity-unknown';

  return (
    <span
      className={`inline-flex items-center gap-ds-2 rounded-full border px-ds-3 py-ds-1 text-ds-caption font-semibold capitalize tracking-wide ${styles} ${className}`}
    >
      {s === 'active' && showPulse ? (
        <span
          className="h-1.5 w-1.5 shrink-0 rounded-full bg-success motion-safe:animate-pulse"
          aria-hidden
        />
      ) : null}
      {formatStatusLabel(status)}
    </span>
  );
}

export default memo(StatusBadge);
