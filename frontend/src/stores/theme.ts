import { create } from 'zustand';
import { theme } from 'antd';

interface ThemeState {
  isDark: boolean;
  toggleTheme: () => void;
}

export const useThemeStore = create<ThemeState>((set) => ({
  isDark: localStorage.getItem('theme') === 'dark',
  toggleTheme: () =>
    set((state) => {
      const next = !state.isDark;
      localStorage.setItem('theme', next ? 'dark' : 'light');
      return { isDark: next };
    }),
}));

export function getAntdTheme(isDark: boolean) {
  const tokens = isDark
    ? {
        colorPrimary: '#4c8dff',
        colorBgBase: '#0f1115',
        colorBgLayout: '#0f1115',
        colorBgContainer: '#16181d',
        colorBgElevated: '#1c1f24',
        colorBorder: '#2b313a',
        colorBorderSecondary: '#252b33',
        colorText: 'rgba(255, 255, 255, 0.88)',
        colorTextSecondary: 'rgba(255, 255, 255, 0.65)',
        colorTextTertiary: 'rgba(255, 255, 255, 0.45)',
        colorFillAlter: 'rgba(255, 255, 255, 0.04)',
      }
    : {
        colorPrimary: '#1677ff',
        colorBgBase: '#ffffff',
        colorBgLayout: '#f5f7fb',
        colorBgContainer: '#ffffff',
        colorBgElevated: '#ffffff',
        colorBorder: '#e6e8ef',
        colorBorderSecondary: '#f0f2f5',
        colorText: 'rgba(0, 0, 0, 0.88)',
        colorTextSecondary: 'rgba(0, 0, 0, 0.65)',
        colorTextTertiary: 'rgba(0, 0, 0, 0.45)',
        colorFillAlter: 'rgba(0, 0, 0, 0.02)',
      };

  return {
    algorithm: isDark ? theme.darkAlgorithm : theme.defaultAlgorithm,
    token: tokens,
  };
}
