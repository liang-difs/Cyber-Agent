import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Suspense, lazy, useEffect } from 'react';
import { useAuthStore } from './stores/auth';
import ProtectedRoute from './components/ProtectedRoute';
import RoleGuard from './components/RoleGuard';
import AppLayout from './components/AppLayout';

const Login = lazy(() => import('./pages/Login'));
const Dashboard = lazy(() => import('./pages/Dashboard'));
const Chat = lazy(() => import('./pages/Chat'));
const Assets = lazy(() => import('./pages/Assets'));
const IoCBulk = lazy(() => import('./pages/IoCBulk'));
const Users = lazy(() => import('./pages/Users'));
const CveSearch = lazy(() => import('./pages/CveSearch'));
const PcapAnalysis = lazy(() => import('./pages/PcapAnalysis'));
const Alerts = lazy(() => import('./pages/Alerts'));
const AttackChain = lazy(() => import('./pages/AttackChain'));
const Reports = lazy(() => import('./pages/Reports'));
const Audit = lazy(() => import('./pages/Audit'));
const Monitor = lazy(() => import('./pages/Monitor'));
const MultiAgent = lazy(() => import('./pages/MultiAgent'));
const RuleEngine = lazy(() => import('./pages/RuleEngine'));
const KnowledgeGraph = lazy(() => import('./pages/KnowledgeGraph'));
const ResponseActions = lazy(() => import('./pages/ResponseActions'));

function RouteFallback() {
  return <div style={{ padding: 24 }}>Loading...</div>;
}

export default function App() {
  const loadFromStorage = useAuthStore((s) => s.loadFromStorage);

  useEffect(() => {
    loadFromStorage();
  }, [loadFromStorage]);

  return (
    <BrowserRouter>
      <Suspense fallback={<RouteFallback />}>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route element={<ProtectedRoute />}>
            <Route element={<AppLayout />}>
              {/* All roles */}
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/chat" element={<Chat />} />
              <Route path="/cve" element={<CveSearch />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/analysis" element={<AttackChain />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/monitor" element={<Monitor />} />
              <Route path="/multi-agent" element={<MultiAgent />} />
              <Route path="/rules" element={<RuleEngine />} />
              <Route path="/knowledge-graph" element={<KnowledgeGraph />} />
              {/* analyst + admin */}
              <Route element={<RoleGuard />}>
                <Route path="/pcap" element={<PcapAnalysis />} />
                <Route path="/ioc" element={<IoCBulk />} />
                <Route path="/assets" element={<Assets />} />
                <Route path="/response-actions" element={<ResponseActions />} />
              </Route>
              {/* admin only */}
              <Route element={<RoleGuard />}>
                <Route path="/audit" element={<Audit />} />
                <Route path="/users" element={<Users />} />
              </Route>
            </Route>
          </Route>
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </Suspense>
    </BrowserRouter>
  );
}
