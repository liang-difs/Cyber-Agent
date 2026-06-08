import { create } from 'zustand';
import type { JwtPayload } from '../types/api';
import { login as loginApi } from '../api/auth';

function parseJwt(token: string): JwtPayload | null {
  try {
    const base64 = token.split('.')[1];
    const json = atob(base64.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(json);
  } catch {
    return null;
  }
}

interface AuthState {
  token: string | null;
  user: JwtPayload | null;
  isAuthenticated: boolean;
  loading: boolean;
  error: string | null;

  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  loadFromStorage: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  token: null,
  user: null,
  isAuthenticated: false,
  loading: true,
  error: null,

  login: async (username, password) => {
    set({ loading: true, error: null });
    try {
      const resp = await loginApi({ username, password });
      localStorage.setItem('token', resp.access_token);
      const payload = parseJwt(resp.access_token);
      set({
        token: resp.access_token,
        user: payload,
        isAuthenticated: true,
        loading: false,
      });
    } catch (err: any) {
      const msg = err.response?.data?.detail || '登录失败';
      set({ error: msg, loading: false });
      throw err;
    }
  },

  logout: () => {
    localStorage.removeItem('token');
    set({ token: null, user: null, isAuthenticated: false, loading: false });
  },

  loadFromStorage: () => {
    const token = localStorage.getItem('token');
    if (!token) {
      set({ loading: false });
      return;
    }
    const payload = parseJwt(token);
    if (!payload || payload.exp * 1000 < Date.now()) {
      localStorage.removeItem('token');
      set({ token: null, user: null, isAuthenticated: false, loading: false });
      return;
    }
    set({ token, user: payload, isAuthenticated: true, loading: false });
  },
}));
