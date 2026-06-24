import React, { forwardRef } from 'react';

/**
 * FormField — label + input + error message + helper text.
 */
export const FormField = forwardRef(function FormField(
  { id, label, error, hint, required = false, children, className = '' },
  _ref
) {
  return (
    <div className={`form-group ${className}`}>
      {label && (
        <label htmlFor={id} className="form-label">
          {label}
          {required && <span className="text-danger ml-1" aria-hidden="true">*</span>}
        </label>
      )}
      {children}
      {error && (
        <p role="alert" className="text-xs text-danger mt-1 flex items-center gap-1">
          <span aria-hidden="true">⚠</span> {error}
        </p>
      )}
      {hint && !error && (
        <p className="text-xs text-text-muted mt-1">{hint}</p>
      )}
    </div>
  );
});

/**
 * TextInput — standard text/email/password input.
 */
export const TextInput = forwardRef(function TextInput(
  { error, className = '', ...props },
  ref
) {
  return (
    <input
      ref={ref}
      className={`form-input w-full ${error ? 'border-danger focus:border-danger focus:shadow-[0_0_0_3px_rgba(239,68,68,0.2)]' : ''} ${className}`}
      aria-invalid={error ? 'true' : undefined}
      {...props}
    />
  );
});

/**
 * SelectInput — styled select dropdown.
 */
export const SelectInput = forwardRef(function SelectInput(
  { error, children, className = '', ...props },
  ref
) {
  return (
    <select
      ref={ref}
      className={`form-input w-full ${error ? 'border-danger' : ''} ${className}`}
      aria-invalid={error ? 'true' : undefined}
      {...props}
    >
      {children}
    </select>
  );
});

/**
 * TextareaInput — styled textarea.
 */
export const TextareaInput = forwardRef(function TextareaInput(
  { error, className = '', rows = 4, ...props },
  ref
) {
  return (
    <textarea
      ref={ref}
      rows={rows}
      className={`form-input w-full resize-y ${error ? 'border-danger' : ''} ${className}`}
      aria-invalid={error ? 'true' : undefined}
      {...props}
    />
  );
});
