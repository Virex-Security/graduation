import { memo } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRightIcon } from '@heroicons/react/24/outline';

/**
 * Compact secondary actions below KPIs.
 */
function QuickLinks({ links, className = '' }) {
  if (!links?.length) return null;
  return (
    <nav
      className={`flex flex-wrap gap-ds-3 pt-ds-2 ${className}`}
      aria-label="Dashboard shortcuts"
    >
      {links.map(({ to, label }) => (
        <Link
          key={to}
          to={to}
          className="group inline-flex items-center gap-ds-2 rounded-ds-lg border border-border-dim/80 bg-bg-secondary/40 px-ds-4 py-ds-3 text-ds-caption font-medium text-text-secondary transition-colors hover:border-brand-primary/40 hover:bg-brand-primary/5 hover:text-brand-primary"
        >
          {label}
          <ArrowRightIcon className="w-3.5 h-3.5 opacity-60 transition-transform group-hover:translate-x-0.5" aria-hidden />
        </Link>
      ))}
    </nav>
  );
}

export default memo(QuickLinks);
