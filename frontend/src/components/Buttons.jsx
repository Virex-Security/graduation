import React from 'react';

/** Primary gradient button */
export function PrimaryButton({ children, className = '', loading = false, ...props }) {
  return (
    <button
      className={`btn btn-primary ${className}`}
      disabled={loading || props.disabled}
      {...props}
    >
      {loading && (
        <svg className="animate-spin -ml-1 w-4 h-4" fill="none" viewBox="0 0 24 24" aria-hidden="true">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
        </svg>
      )}
      {children}
    </button>
  );
}

/** Secondary outlined button */
export function SecondaryButton({ children, className = '', ...props }) {
  return (
    <button className={`btn btn-secondary ${className}`} {...props}>
      {children}
    </button>
  );
}

/** Danger-styled button */
export function DangerButton({ children, className = '', ...props }) {
  return (
    <button className={`btn btn-danger ${className}`} {...props}>
      {children}
    </button>
  );
}

/** Ghost button (no background) */
export function GhostButton({ children, className = '', ...props }) {
  return (
    <button className={`btn btn-ghost ${className}`} {...props}>
      {children}
    </button>
  );
}

/** Round icon button */
export function IconButton({ children, label, className = '', ...props }) {
  return (
    <button
      className={`btn btn-icon btn-ghost ${className}`}
      aria-label={label}
      {...props}
    >
      {children}
    </button>
  );
}
