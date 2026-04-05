import { useState, useCallback, useRef } from 'react';
import { ToastContext } from './ToastContext';


export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const toastIdRef = useRef(0);

  const addToast = useCallback((message, type = 'info', duration = 4000) => {
    const id = ++toastIdRef.current;
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), duration);
  }, []);

  const removeToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const typeStyles = {
    success: 'bg-success/10 border-success/30 text-success',
    error: 'bg-danger/10 border-danger/30 text-danger',
    warning: 'bg-warning/10 border-warning/30 text-warning',
    info: 'bg-info/10 border-info/30 text-info',
  };

  const typeIcons = {
    success: '✓',
    error: '✕',
    warning: '⚠',
    info: 'ℹ',
  };

  return (
    <ToastContext.Provider value={{ addToast }}>
      {children}
      <div
        role="region"
        aria-label="Notifications"
        aria-live="polite"
        className="fixed bottom-6 right-6 z-[9999] flex flex-col gap-3 max-w-sm"
      >
        {toasts.map((toast) => (
          <div
            key={toast.id}
            role="alert"
            className={`flex items-start gap-3 px-4 py-3 rounded-xl border backdrop-blur-md shadow-lg animate-[slideIn_0.3s_ease] ${typeStyles[toast.type] || typeStyles.info}`}
          >
            <span className="text-lg leading-none mt-[1px]" aria-hidden="true">
              {typeIcons[toast.type]}
            </span>
            <p className="text-sm font-medium flex-1">{toast.message}</p>
            <button
              onClick={() => removeToast(toast.id)}
              aria-label="Dismiss notification"
              className="opacity-60 hover:opacity-100 ml-2 text-current"
            >
              ×
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

