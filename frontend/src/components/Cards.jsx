import React from 'react';

/**
 * StatCard — shows a metric with icon, label, value, and optional change.
 * Props: icon (HeroIcon), label, value, change, changeType ('up'|'down'|'neutral'), accentColor
 */
export function StatCard({ icon: Icon, label, value, change, changeType = 'neutral', accentColor = '#9a277d', skeleton = false }) {
  if (skeleton) {
    return (
      <div className="card flex items-center gap-5">
        <div className="w-12 h-12 rounded-xl bg-bg-secondary animate-pulse" />
        <div className="flex flex-col gap-2 flex-1">
          <div className="h-3 bg-bg-secondary rounded animate-pulse w-3/4" />
          <div className="h-6 bg-bg-secondary rounded animate-pulse w-1/2" />
        </div>
      </div>
    );
  }

  const changeColors = {
    up: 'text-success',
    down: 'text-danger',
    neutral: 'text-text-muted',
  };

  return (
    <div className="card hover:scale-[1.02] hover:-translate-y-1 cursor-default">
      <div className="flex items-start gap-5">
        <div
          className="w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0"
          style={{ background: `${accentColor}22`, color: accentColor }}
        >
          {Icon && <Icon className="w-6 h-6" />}
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-xs font-semibold text-text-muted uppercase tracking-wider truncate">{label}</p>
          <p className="text-2xl font-bold text-text-primary mt-1 tabular-nums">{value ?? '—'}</p>
          {change !== undefined && (
            <p className={`text-xs mt-1 ${changeColors[changeType]}`}>{change}</p>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * InfoCard — a generic card wrapper with optional title and action.
 */
export function InfoCard({ title, action, children, className = '' }) {
  return (
    <div className={`card ${className}`}>
      {(title || action) && (
        <div className="flex items-center justify-between mb-5">
          {title && <h3 className="text-sm font-semibold text-text-muted uppercase tracking-wider">{title}</h3>}
          {action && <div>{action}</div>}
        </div>
      )}
      {children}
    </div>
  );
}
