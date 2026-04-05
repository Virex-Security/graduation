/**
 * ToastContext definition — shared between ToastContext.jsx and useToast.js
 */
import { createContext } from 'react';

export const ToastContext = createContext({
  toasts: [],
  addToast: () => {},
  removeToast: () => {},
});
