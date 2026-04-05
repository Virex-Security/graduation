import { memo } from 'react';

/**
 * Responsive grid for KPI cards (1 → 2 → 4 columns).
 */
function KpiGrid({ children, className = '' }) {
  return (
    <div
      className={`grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-ds-5 ${className}`}
    >
      {children}
    </div>
  );
}

export default memo(KpiGrid);
