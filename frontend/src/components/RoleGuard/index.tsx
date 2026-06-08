import { Navigate, Outlet } from 'react-router-dom';
import { useAuthStore } from '../../stores/auth';

/** Routes accessible to each role. */
const ROLE_ROUTES: Record<string, string[]> = {
  viewer: ['/dashboard', '/chat', '/cve', '/alerts', '/analysis', '/reports', '/monitor'],
  analyst: ['/dashboard', '/chat', '/cve', '/ioc', '/pcap', '/assets', '/alerts', '/analysis', '/reports', '/monitor'],
  admin: ['*'],
};

export default function RoleGuard() {
  const user = useAuthStore((s) => s.user);
  const role = user?.role || 'viewer';
  const allowed = ROLE_ROUTES[role] || ROLE_ROUTES.viewer;

  if (allowed.includes('*')) return <Outlet />;

  // Check if current path starts with any allowed route
  const path = window.location.pathname;
  const hasAccess = allowed.some((r) => path === r || path.startsWith(r + '/'));

  if (!hasAccess) return <Navigate to="/dashboard" replace />;
  return <Outlet />;
}
