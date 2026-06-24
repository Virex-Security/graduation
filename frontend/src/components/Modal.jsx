import React, { useEffect, useRef } from 'react';
import { XMarkIcon } from '@heroicons/react/24/outline';
import { PrimaryButton, SecondaryButton } from './Buttons';

/**
 * Modal — accessible dialog with focus trap and keyboard close.
 * Props: isOpen, onClose, title, children, footer, size ('sm'|'md'|'lg'|'xl')
 */
export default function Modal({ isOpen, onClose, title, children, footer, size = 'md' }) {
  const overlayRef = useRef(null);
  const dialogRef = useRef(null);

  useEffect(() => {
    if (!isOpen) return;
    const prev = document.activeElement;
    dialogRef.current?.focus();
    return () => prev?.focus();
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    const handleKey = (e) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handleKey);
    return () => document.removeEventListener('keydown', handleKey);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const sizeClasses = {
    sm: 'max-w-sm',
    md: 'max-w-lg',
    lg: 'max-w-2xl',
    xl: 'max-w-4xl',
  };

  return (
    <div
      ref={overlayRef}
      role="presentation"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
      onClick={(e) => { if (e.target === overlayRef.current) onClose(); }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
        tabIndex={-1}
        className={`relative w-full ${sizeClasses[size]} card outline-none`}
      >
        {/* Header */}
        <div className="flex items-center justify-between mb-5">
          {title && (
            <h2 id="modal-title" className="text-lg font-bold text-text-primary normal-case tracking-normal">
              {title}
            </h2>
          )}
          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="btn btn-icon btn-ghost ml-auto"
          >
            <XMarkIcon className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="text-text-secondary leading-relaxed">{children}</div>

        {/* Footer */}
        {footer && (
          <div className="flex items-center justify-end gap-3 mt-6 pt-4 border-t border-border-dim">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * ConfirmModal — quick confirm/cancel dialog.
 */
export function ConfirmModal({ isOpen, onClose, onConfirm, title, message, confirmLabel = 'Confirm', danger = false, loading = false }) {
  return (
    <Modal isOpen={isOpen} onClose={onClose} title={title} size="sm"
      footer={
        <>
          <SecondaryButton onClick={onClose} disabled={loading}>Cancel</SecondaryButton>
          {danger
            ? <button className="btn btn-danger" onClick={onConfirm} disabled={loading}>{loading ? 'Processing…' : confirmLabel}</button>
            : <PrimaryButton onClick={onConfirm} loading={loading}>{confirmLabel}</PrimaryButton>
          }
        </>
      }
    >
      <p>{message}</p>
    </Modal>
  );
}
