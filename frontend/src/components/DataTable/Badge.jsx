import { memo } from 'react';

/** Severity / status / tag pill */
function Badge({ label, className = '' }) {
  return (
    <span
      className={`inline-flex items-center px-ds-3 py-ds-1 rounded-full text-ds-caption font-bold uppercase tracking-ds-wide border ${className}`}
    >
      {label}
    </span>
  );
}

export default memo(Badge);
