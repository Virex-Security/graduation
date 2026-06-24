import React from 'react';

export function Skeleton({ className = '', variant = 'rect', width, height }) {
  const baseClasses = "bg-bg-secondary animate-pulse rounded";
  const variantClasses = variant === 'circle' ? 'rounded-full' : 'rounded-xl';
  
  const style = {
    width: width || '100%',
    height: height || '1rem',
  };

  return (
    <div 
      className={`${baseClasses} ${variantClasses} ${className}`}
      style={style}
    />
  );
}

export function StatSkeleton() {
  return (
    <div className="card flex items-center gap-5">
      <Skeleton variant="rect" width="3rem" height="3rem" />
      <div className="flex flex-col gap-2 flex-1">
        <Skeleton width="40%" height="0.75rem" />
        <Skeleton width="60%" height="1.5rem" />
      </div>
    </div>
  );
}

export function TableSkeleton({ rows = 5, cols = 4 }) {
  return (
    <div className="space-y-4">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex gap-4 p-4 border-b border-border-dim/50">
          {Array.from({ length: cols }).map((_, j) => (
            <Skeleton key={j} width={`${20 + (j * 10)}%`} height="1rem" />
          ))}
        </div>
      ))}
    </div>
  );
}
