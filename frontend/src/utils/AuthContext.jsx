/**
 * AuthContext — cookie-based authentication (no localStorage).
 *
 * The backend sets an httpOnly cookie on login. The React app
 * never touches the token directly — it just calls /api/user
 * to check whether a valid session exists.
 *
 * This eliminates the XSS token-theft vulnerability that existed
 * when the token was stored in localStorage.
 */
import { useState, useEffect, useCallback } from 'react';
import { AuthContext } from './AuthContext';
import API from '../api/client';

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // On mount: check if the httpOnly cookie gives us a valid session
  useEffect(() => {
    API.get('/user')
      .then((data) => setUser(data.user || data))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  const login = useCallback(async (credentials) => {
    // POST credentials → backend sets httpOnly cookie
    const data = await API.post('/auth/login', credentials);
    // Fetch user info after login (cookie is set, no token in JS)
    const me = await API.get('/user').catch(() => null);
    setUser(me?.user || me || { role: data.role });
    return data;
  }, []);

  const logout = useCallback(async () => {
    try {
      await API.post('/auth/logout', {});
    } catch (err) {
      console.error('Logout error:', err);
    }
    setUser(null);
    window.location.href = '/login';
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}
