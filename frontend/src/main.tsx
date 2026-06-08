import React, { useEffect } from 'react';
import ReactDOM from 'react-dom/client';
import { ConfigProvider } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import App from './App';
import ErrorBoundary from './components/ErrorBoundary';
import { useThemeStore, getAntdTheme } from './stores/theme';
import './theme.css';
import './markdown.css';

function Root() {
  const isDark = useThemeStore((s) => s.isDark);

  useEffect(() => {
    document.documentElement.dataset.theme = isDark ? 'dark' : 'light';
  }, [isDark]);

  return (
    <ErrorBoundary>
      <ConfigProvider locale={zhCN} theme={getAntdTheme(isDark)}>
        <App />
      </ConfigProvider>
    </ErrorBoundary>
  );
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>,
);
