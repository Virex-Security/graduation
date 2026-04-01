import { useState, useEffect, useCallback } from 'react';
import { AuthContext } from './AuthContext';
import API from '../api/client';


export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('virex_token');
    if (token) {
      API.get('/auth/user')
        .then((data) => setUser(data.user || data))
        .catch(() => localStorage.removeItem('virex_token'))
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  const login = useCallback(async (credentials) => {
    const data = await API.post('/auth/login', credentials);
    if (data.token) localStorage.setItem('virex_token', data.token);
    setUser(data.user || data);
    return data;
  }, []);

  const logout = useCallback(async () => {
    try { await API.post('/auth/logout', {}); } catch (err) { console.error('Logout error:', err); }
    localStorage.removeItem('virex_token');
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

