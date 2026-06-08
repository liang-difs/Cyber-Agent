import { useState, useEffect, useCallback } from 'react';
import { Card, Row, Col, Tag, Statistic, Button, Space, message } from 'antd';
import {
  CheckCircleFilled,
  CloseCircleFilled,
  WarningFilled,
  ReloadOutlined,
  DatabaseOutlined,
} from '@ant-design/icons';
import { getDetailedHealth } from '../../api/monitor';
import type { HealthResponse, HealthCheck } from '../../types/api';
import LLMModelSwitcher from '../../components/LLMModelSwitcher';
import { useAuthStore } from '../../stores/auth';

const STATUS_CONFIG: Record<string, { color: string; icon: React.ReactNode }> = {
  ok: { color: 'green', icon: <CheckCircleFilled style={{ color: '#52c41a', fontSize: 24 }} /> },
  healthy: { color: 'green', icon: <CheckCircleFilled style={{ color: '#52c41a', fontSize: 24 }} /> },
  error: { color: 'red', icon: <CloseCircleFilled style={{ color: '#ff4d4f', fontSize: 24 }} /> },
  degraded: { color: 'orange', icon: <WarningFilled style={{ color: '#faad14', fontSize: 24 }} /> },
  no_workers: { color: 'orange', icon: <WarningFilled style={{ color: '#faad14', fontSize: 24 }} /> },
  unconfigured: { color: 'default', icon: <DatabaseOutlined style={{ color: '#aaa', fontSize: 24 }} /> },
};

const SERVICE_LABELS: Record<string, string> = {
  postgresql: 'PostgreSQL',
  redis: 'Redis',
  elasticsearch: 'Elasticsearch',
  celery: 'Celery Worker',
};

export default function Monitor() {
  const user = useAuthStore((s) => s.user);
  const canSwitchLlm = user?.role === 'admin';
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchHealth = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getDetailedHealth();
      setHealth(data);
    } catch {
      message.error('获取系统状态失败');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    const timer = setInterval(fetchHealth, 30000);
    return () => clearInterval(timer);
  }, [fetchHealth]);

  const overallStatus = health?.status || 'unknown';
  const overallConfig = STATUS_CONFIG[overallStatus] || STATUS_CONFIG.unconfigured;

  return (
    <div className="page-shell" style={{ flexDirection: 'column' }}>
      <Card
        title="系统监控"
        className="page-card-fill"
        style={{ display: 'flex', flexDirection: 'column' }}
        extra={
          <Button icon={<ReloadOutlined />} onClick={fetchHealth} loading={loading}>
            刷新
          </Button>
        }
      >
        <div
          style={{
            marginBottom: 24,
            padding: 16,
            borderRadius: 12,
            background: 'var(--app-surface-elevated)',
            border: '1px solid var(--app-border)',
          }}
        >
          <Space direction="vertical" size={10} style={{ width: '100%' }}>
            <Space wrap align="center" style={{ justifyContent: 'space-between', width: '100%' }}>
              <Space direction="vertical" size={2}>
                <div style={{ fontSize: 14, fontWeight: 600 }}>LLM 外部 API 状态</div>
                <div style={{ fontSize: 12, color: 'var(--app-text-secondary)' }}>
                  {canSwitchLlm
                    ? '当前以 DeepSeek API 为主；如需切换默认外部模型，可直接使用下方按钮。'
                    : '当前仅展示后端状态，切换权限仅限管理员。'}
                </div>
              </Space>
              <LLMModelSwitcher variant="panel" editable={canSwitchLlm} onSwitched={() => void fetchHealth()} />
            </Space>
          </Space>
        </div>

        <Row gutter={[16, 16]} style={{ marginBottom: 24, alignItems: 'stretch' }}>
          <Col xs={24} sm={12} lg={6} style={{ display: 'flex' }}>
            <Card className="page-card-fill" style={{ width: '100%', height: '100%' }}>
              <Space>
                {overallConfig.icon}
                <div>
                  <div style={{ fontSize: 14, color: '#888' }}>整体状态</div>
                  <Tag color={overallConfig.color} style={{ fontSize: 16 }}>
                    {overallStatus.toUpperCase()}
                  </Tag>
                </div>
              </Space>
            </Card>
          </Col>
          <Col xs={24} sm={12} lg={6} style={{ display: 'flex' }}>
            <Card className="page-card-fill" style={{ width: '100%', height: '100%' }}>
              <Statistic title="版本" value={health?.version || '-'} />
            </Card>
          </Col>
          <Col xs={24} lg={12} style={{ display: 'flex' }}>
            <Card className="page-card-fill" style={{ width: '100%', height: '100%' }}>
              <Statistic
                title="最后检查"
                value={health?.timestamp ? new Date(health.timestamp).toLocaleString('zh-CN') : '-'}
              />
            </Card>
          </Col>
        </Row>

        <Row gutter={[16, 16]} style={{ alignItems: 'stretch' }}>
          {health?.checks &&
            Object.entries(health.checks).map(([key, check]: [string, HealthCheck]) => {
              const config = STATUS_CONFIG[check.status] || STATUS_CONFIG.unconfigured;
              return (
                <Col xs={24} sm={12} xl={6} key={key} style={{ display: 'flex' }}>
                  <Card className="page-card-fill" style={{ width: '100%', height: '100%' }}>
                    <Space direction="vertical" style={{ width: '100%' }}>
                      <Space>
                        {config.icon}
                        <span style={{ fontWeight: 600 }}>{SERVICE_LABELS[key] || key}</span>
                      </Space>
                      <Tag color={config.color}>{check.status.toUpperCase()}</Tag>
                      {check.cluster_status && (
                        <div style={{ fontSize: 12, color: '#888' }}>
                          Cluster: {check.cluster_status}
                        </div>
                      )}
                      {check.workers != null && (
                        <div style={{ fontSize: 12, color: '#888' }}>
                          Workers: {check.workers}
                        </div>
                      )}
                      {check.detail && (
                        <div style={{ fontSize: 12, color: '#888', wordBreak: 'break-all' }}>
                          {check.detail}
                        </div>
                      )}
                    </Space>
                  </Card>
                </Col>
              );
            })}
        </Row>
      </Card>
    </div>
  );
}
