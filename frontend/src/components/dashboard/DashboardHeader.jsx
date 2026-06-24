import { memo } from 'react';

/**
 * Dashboard page title + supporting line. Keeps hierarchy and spacing consistent.
 */
function DashboardHeader({ title, description, className = '' }) {
  return (
    <header className={`space-y-ds-2 ${className}`}>
      <h1 className="text-ds-title font-bold text-text-primary tracking-ds-snug">{title}</h1>
      {description ? (
        <p className="text-ds-body-sm text-text-muted max-w-2xl leading-relaxed">{description}</p>
      ) : null}
    </header>
  );
}

export default memo(DashboardHeader);
