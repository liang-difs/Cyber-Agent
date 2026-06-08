import { useState } from 'react';
import { Layout, Menu, Button, Space, Tag, Grid, Divider, Typography } from 'antd';
import {
  MessageOutlined,
  BugOutlined,
  BulbOutlined,
  BulbFilled,
  LogoutOutlined,
  FileSearchOutlined,
  SearchOutlined,
  AlertOutlined,
  ApartmentOutlined,
  FileTextOutlined,
  AuditOutlined,
  DashboardOutlined,
  HomeOutlined,
  DatabaseOutlined,
  TeamOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  RobotOutlined,
  SafetyCertificateOutlined,
  NodeIndexOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import { useThemeStore } from '../../stores/theme';
import { useAuthStore } from '../../stores/auth';

const { Sider, Content } = Layout;
const { useBreakpoint } = Grid;

/** Menu items visible to each role. */
const ROLE_MENU: Record<string, string[]> = {
  // viewer: 只读 — 对话、CVE、告警(只读)、攻击链(只读)、报告(只读)、监控
  viewer: ['/dashboard', '/chat', '/cve', '/alerts', '/analysis', '/reports', '/monitor', '/multi-agent', '/rules', '/knowledge-graph'],
  // analyst: 对话 + 工具查询 + 研判 + 报告生成 — 增加 PCAP、IoC、资产管理、响应动作
  analyst: ['/dashboard', '/chat', '/cve', '/ioc', '/pcap', '/assets', '/alerts', '/analysis', '/reports', '/monitor', '/multi-agent', '/rules', '/knowledge-graph', '/response-actions'],
  // admin: 全部权限
  admin: ['/dashboard', '/chat', '/cve', '/ioc', '/pcap', '/assets', '/alerts', '/analysis', '/reports', '/audit', '/monitor', '/users', '/multi-agent', '/rules', '/knowledge-graph', '/response-actions'],
};

function useMenuItems() {
  const user = useAuthStore((s) => s.user);
  const role = user?.role || 'viewer';
  const allowed = new Set(ROLE_MENU[role] || ROLE_MENU.viewer);

  const allItems = [
    { key: '/dashboard', icon: <HomeOutlined />, label: '态势总览' },
    { key: '/chat', icon: <MessageOutlined />, label: '智能对话' },
    { key: '/cve', icon: <BugOutlined />, label: 'CVE 数据库' },
    { key: '/ioc', icon: <SearchOutlined />, label: 'IoC 批量查询' },
    { type: 'divider' as const },
    { key: '/pcap', icon: <FileSearchOutlined />, label: 'PCAP 分析' },
    { key: '/assets', icon: <DatabaseOutlined />, label: '资产管理' },
    { key: '/alerts', icon: <AlertOutlined />, label: '告警管理' },
    { key: '/analysis', icon: <ApartmentOutlined />, label: '攻击链分析' },
    { key: '/reports', icon: <FileTextOutlined />, label: '报告生成' },
    { type: 'divider' as const },
    { key: '/multi-agent', icon: <RobotOutlined />, label: '多智能体' },
    { key: '/rules', icon: <SafetyCertificateOutlined />, label: '规则引擎' },
    { key: '/knowledge-graph', icon: <NodeIndexOutlined />, label: '知识图谱' },
    { key: '/response-actions', icon: <ThunderboltOutlined />, label: '响应动作' },
    { type: 'divider' as const },
    { key: '/audit', icon: <AuditOutlined />, label: '审计日志' },
    { key: '/monitor', icon: <DashboardOutlined />, label: '系统监控' },
    { key: '/users', icon: <TeamOutlined />, label: '用户管理' },
  ];

  return allItems.filter((item) => !item.key || allowed.has(item.key));
}

export default function AppLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const screens = useBreakpoint();
  const [collapsed, setCollapsed] = useState(false);
  const { isDark, toggleTheme } = useThemeStore();
  const { user, logout } = useAuthStore();
  const menuItems = useMenuItems();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <Layout style={{ height: '100vh', overflow: 'hidden' }}>
      <Sider
        width={220}
        collapsible
        trigger={null}
        collapsed={collapsed}
        collapsedWidth={screens.lg ? 64 : 0}
        breakpoint="lg"
        onCollapse={setCollapsed}
        style={{
          position: 'sticky',
          top: 0,
          height: '100vh',
          background: 'var(--app-surface)',
          borderRight: '1px solid var(--app-border)',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
          <div
            style={{
              flex: '0 0 auto',
              padding: collapsed ? '16px 8px 10px' : '18px 20px 12px',
              fontWeight: 700,
              fontSize: collapsed ? 13 : 18,
              textAlign: collapsed ? 'center' : 'left',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            }}
          >
            {collapsed ? 'CSA' : 'CyberSec Agent'}
          </div>
          <div style={{ flex: '1 1 auto', minHeight: 0, overflowY: 'auto', overflowX: 'hidden' }}>
            <Menu
              mode="inline"
              selectedKeys={[location.pathname]}
              items={menuItems}
              onClick={({ key }) => navigate(key)}
              style={{ borderRight: 'none', background: 'transparent' }}
            />
          </div>
          <div style={{
            flex: '0 0 auto',
            marginTop: 'auto',
            padding: collapsed ? '12px 8px 14px' : '12px 16px 16px',
            borderTop: '1px solid var(--app-border)',
            background: 'var(--app-surface)',
          }}>
            {collapsed ? (
              <Space direction="vertical" style={{ width: '100%' }} align="center">
                <Tag color="blue" style={{ margin: 0 }}>{user?.role || 'user'}</Tag>
                <Space>
                  <Button type="text" icon={isDark ? <BulbFilled /> : <BulbOutlined />} onClick={toggleTheme} size="small" />
                  <Button type="text" icon={<LogoutOutlined />} onClick={handleLogout} size="small" danger />
                  <Button type="text" icon={<MenuUnfoldOutlined />} onClick={() => setCollapsed(false)} size="small" />
                </Space>
              </Space>
            ) : (
              <>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                  <Space size={8} wrap>
                    <Tag color="blue">{user?.role || 'user'}</Tag>
                    {user?.tenant_id && <Tag color="geekblue">{user.tenant_id}</Tag>}
                  </Space>
                  <Button type="text" icon={<MenuFoldOutlined />} onClick={() => setCollapsed(true)} size="small" />
                </div>
                <Divider style={{ margin: '12px 0 10px' }} />
                <Space style={{ width: '100%', justifyContent: 'space-between' }}>
                  <Button type="text" icon={isDark ? <BulbFilled /> : <BulbOutlined />} onClick={toggleTheme}>
                    主题
                  </Button>
                  <Button type="text" icon={<LogoutOutlined />} onClick={handleLogout} danger>
                    退出
                  </Button>
                </Space>
              </>
            )}
          </div>
        </div>
      </Sider>
      <Layout style={{ flex: 1, minWidth: 0, minHeight: 0, display: 'flex', flexDirection: 'column', background: 'var(--app-bg)' }}>
        <Content style={{ flex: 1, padding: screens.md ? 24 : 12, minWidth: 0, display: 'flex', flexDirection: 'column', minHeight: 0, background: 'var(--app-bg)', overflow: 'hidden' }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 12,
              marginBottom: 16,
              padding: '10px 14px',
              borderRadius: 12,
              background: 'var(--app-surface)',
              border: '1px solid var(--app-border)',
              boxShadow: 'var(--app-shadow)',
            }}
          >
            <Button type="text" icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />} onClick={() => setCollapsed((value) => !value)}>
              {collapsed ? '展开侧栏' : '收起侧栏'}
            </Button>
            <Typography.Text type="secondary" ellipsis style={{ maxWidth: 260 }}>
              {user?.role ? `角色：${user.role}` : '角色：user'}
              {user?.tenant_id ? ` · 租户：${user.tenant_id}` : ''}
            </Typography.Text>
          </div>
          <div style={{ flex: 1, minHeight: 0, display: 'flex', overflow: 'hidden' }}>
            <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', overflowX: 'hidden' }}>
              <Outlet />
            </div>
          </div>
        </Content>
      </Layout>
    </Layout>
  );
}
