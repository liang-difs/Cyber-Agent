import { useState, useEffect, useCallback } from 'react';
import { Card, Row, Col, Statistic, Table, Tag, Space, Button, message } from 'antd';
import {
  AlertOutlined,
  BugOutlined,
  SafetyCertificateOutlined,
  DashboardOutlined,
  ReloadOutlined,
  CheckCircleFilled,
  CloseCircleFilled,
  WarningFilled,
} from '@ant-design/icons';
import ReactECharts from 'echarts-for-react';
import { getDashboard } from '../../api/dashboard';
import type { DashboardData, DashboardAlertSummary } from '../../types/api';

import { SEVERITY_HEX_COLORS as SEVERITY_COLORS } from '../../constants/severity';

const HEALTH_ICON: Record<string, React.ReactNode> = {
  healthy: <CheckCircleFilled style={{ color: '#52c41a' }} />,
  degraded: <WarningFilled style={{ color: '#faad14' }} />,
  error: <CloseCircleFilled style={{ color: '#ff4d4f' }} />,
};

function trendChartOption(data: Array<{ date: string; critical: number; high: number; medium: number; low: number }>) {
  const dates = data.map((d) => d.date.slice(5));
  const sevs = [
    { key: 'critical' as const, name: 'Critical', color: '#ff4d4f' },
    { key: 'high' as const, name: 'High', color: '#fa8c16' },
    { key: 'medium' as const, name: 'Medium', color: '#faad14' },
    { key: 'low' as const, name: 'Low', color: '#52c41a' },
  ];
  return {
    tooltip: { trigger: 'axis' },
    legend: { bottom: 0, textStyle: { fontSize: 11 } },
    grid: { left: 50, right: 20, top: 10, bottom: 40 },
    xAxis: { type: 'category', data: dates, axisLabel: { fontSize: 11 } },
    yAxis: { type: 'value', minInterval: 1 },
    series: sevs.map((s) => ({
      name: s.name,
      type: 'bar',
      stack: 'total',
      data: data.map((d) => d[s.key] || 0),
      itemStyle: { color: s.color },
      barMaxWidth: 30,
    })),
  };
}

function severityPieOption(data: Record<string, number>, title: string) {
  const entries = Object.entries(data).map(([name, value]) => ({
    name: name.toUpperCase(),
    value,
    itemStyle: { color: SEVERITY_COLORS[name.toLowerCase()] || '#999' },
  }));
  return {
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { bottom: 0, textStyle: { fontSize: 12 } },
    series: [
      {
        type: 'pie',
        radius: ['40%', '70%'],
        center: ['50%', '45%'],
        data: entries,
        label: { show: false },
        emphasis: { label: { show: true, fontSize: 14, fontWeight: 'bold' } },
      },
    ],
    title: { text: title, left: 'center', top: 0, textStyle: { fontSize: 14 } },
  };
}

const alertColumns = [
  { title: '规则', dataIndex: 'rule_id', key: 'rule_id', ellipsis: true },
  {
    title: '严重等级',
    dataIndex: 'severity',
    key: 'severity',
    render: (s: string) => <Tag color={SEVERITY_COLORS[s] || 'default'}>{s?.toUpperCase()}</Tag>,
  },
  { title: '源 IP', dataIndex: 'src_ip', key: 'src_ip', ellipsis: true },
  { title: '状态', dataIndex: 'status', key: 'status' },
  {
    title: '时间',
    dataIndex: 'created_at',
    key: 'created_at',
    render: (t: string) => (t ? new Date(t).toLocaleString('zh-CN') : '-'),
  },
];

const cveColumns = [
  { title: 'CVE ID', dataIndex: 'id', key: 'id' },
  {
    title: '严重等级',
    dataIndex: 'severity',
    key: 'severity',
    render: (s: string) => <Tag color={SEVERITY_COLORS[s] || 'default'}>{s?.toUpperCase()}</Tag>,
  },
  { title: 'CVSS', dataIndex: 'cvss_score', key: 'cvss_score' },
  { title: '发布日期', dataIndex: 'published', key: 'published' },
];

export default function Dashboard() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const resp = await getDashboard();
      setData(resp);
    } catch {
      message.error('获取仪表盘数据失败');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const timer = setInterval(fetchData, 30000);
    return () => clearInterval(timer);
  }, [fetchData]);

  if (!data) return null;

  const alerts = data.alerts;
  const cve = data.cve;
  const health = data.health;
  const healthIcon = HEALTH_ICON[health.status] || HEALTH_ICON.error;

  return (
    <div className="page-shell" style={{ flexDirection: 'column', gap: 16 }}>
      {/* Row 1: Stats cards */}
      <Row gutter={[16, 16]}>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title="告警总数"
              value={alerts.total}
              prefix={<AlertOutlined style={{ color: '#1890ff' }} />}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title="Critical"
              value={alerts.by_severity?.critical || 0}
              valueStyle={{ color: '#ff4d4f' }}
              prefix={<BugOutlined />}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title="High"
              value={alerts.by_severity?.high || 0}
              valueStyle={{ color: '#fa8c16' }}
              prefix={<BugOutlined />}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Space>
              {healthIcon}
              <div>
                <div style={{ fontSize: 14, color: '#888' }}>系统状态</div>
                <Tag
                  color={health.status === 'healthy' ? 'green' : 'orange'}
                  style={{ fontSize: 16 }}
                >
                  {health.status.toUpperCase()}
                </Tag>
                {health.llm_model && (
                  <div style={{ fontSize: 12, color: '#888', marginTop: 4 }}>
                    {health.llm_model}
                  </div>
                )}
              </div>
            </Space>
          </Card>
        </Col>
      </Row>

      {/* Row 2: Pie charts */}
      <Row gutter={[16, 16]}>
        <Col xs={24} md={12}>
          <Card title="告警严重等级分布" size="small">
            {Object.keys(alerts.by_severity).length > 0 ? (
              <ReactECharts
                option={severityPieOption(alerts.by_severity, '')}
                style={{ height: 250 }}
              />
            ) : (
              <div style={{ textAlign: 'center', padding: 40, color: '#999' }}>暂无告警数据</div>
            )}
          </Card>
        </Col>
        <Col xs={24} md={12}>
          <Card title="CVE 严重等级分布" size="small">
            {Object.keys(cve.by_severity).length > 0 ? (
              <ReactECharts
                option={severityPieOption(cve.by_severity, '')}
                style={{ height: 250 }}
              />
            ) : (
              <div style={{ textAlign: 'center', padding: 40, color: '#999' }}>暂无 CVE 数据</div>
            )}
          </Card>
        </Col>
      </Row>

      {/* Row 2.5: Alert trend */}
      {alerts.trend && alerts.trend.length > 0 && (
        <Card title="近 14 天告警趋势" size="small">
          <ReactECharts option={trendChartOption(alerts.trend)} style={{ height: 200 }} />
        </Card>
      )}

      {/* Row 3: Recent tables */}
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <Card
            title="最近告警"
            size="small"
            extra={<Tag>{alerts.total} 条</Tag>}
          >
            <Table
              dataSource={alerts.recent}
              columns={alertColumns}
              rowKey="id"
              size="small"
              pagination={false}
              locale={{ emptyText: '暂无告警' }}
            />
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card
            title="最近 CVE"
            size="small"
            extra={<Tag>{cve.total} 条</Tag>}
          >
            <Table
              dataSource={cve.recent}
              columns={cveColumns}
              rowKey="id"
              size="small"
              pagination={false}
              locale={{ emptyText: '暂无 CVE 数据' }}
            />
          </Card>
        </Col>
      </Row>

      {/* Row 4: Health services */}
      <Card title="服务健康" size="small" extra={<Button icon={<ReloadOutlined />} size="small" onClick={fetchData} loading={loading} />}>
        <Row gutter={[16, 16]}>
          {Object.entries(health.services).map(([key, status]) => {
            const icon = HEALTH_ICON[status] || <DashboardOutlined style={{ color: '#999' }} />;
            const labels: Record<string, string> = {
              postgresql: 'PostgreSQL',
              redis: 'Redis',
              elasticsearch: 'Elasticsearch',
              celery: 'Celery',
              llm: 'LLM',
            };
            return (
              <Col xs={12} sm={8} md={4} key={key}>
                <Card size="small">
                  <Space>
                    {icon}
                    <div>
                      <div style={{ fontWeight: 600, fontSize: 13 }}>{labels[key] || key}</div>
                      <Tag
                        color={status === 'ok' ? 'green' : status === 'unconfigured' ? 'default' : 'orange'}
                        style={{ fontSize: 11 }}
                      >
                        {status}
                      </Tag>
                    </div>
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
