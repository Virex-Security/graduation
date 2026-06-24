/**
 * AuthContext definition — shared between AuthContext.jsx (provider)
 * and useAuth.js (hook).
 */
import { createContext } from 'react';

export const AuthContext = createContext({
  user: null,
  loading: true,
  login: async () => {},
  logout: async () => {},
});
