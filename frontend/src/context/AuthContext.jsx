import React, { createContext, useContext, useState, useEffect } from 'react';
import { login as apiLogin, getCurrentUser } from '../services/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const defaultUser = { username: 'ThreatLense Analyst', role: 'admin' };
  const [user, setUser] = useState(() => {
    try {
      const saved = localStorage.getItem('ids_user');
      return saved ? JSON.parse(saved) : defaultUser;
    } catch {
      return defaultUser;
    }
  });
  const [token, setToken] = useState(() => localStorage.getItem('ids_token') || 'threatlense-offline-active-token');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!localStorage.getItem('ids_token')) {
      localStorage.setItem('ids_token', 'threatlense-offline-active-token');
      localStorage.setItem('ids_user', JSON.stringify(defaultUser));
    }
  }, []);

  const login = async (username, password) => {
    const data = await apiLogin(username, password);
    localStorage.setItem('ids_token', data.access_token);
    const userInfo = { username: data.username, role: data.role };
    localStorage.setItem('ids_user', JSON.stringify(userInfo));
    setToken(data.access_token);
    setUser(userInfo);
    setLoading(false);
    return data;
  };

  const logout = () => {
    localStorage.removeItem('ids_token');
    localStorage.removeItem('ids_user');
    setToken(null);
    setUser(null);
    setLoading(false);
  };

  return (
    <AuthContext.Provider value={{ user, token, isAuthenticated: !!token, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
