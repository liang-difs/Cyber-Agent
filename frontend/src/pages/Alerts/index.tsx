import { useState, useCallback, useEffect } from 'react';
import { Card, Table, Tag, Button, Drawer, Descriptions, message, Tooltip, Grid, Alert as AntAlert, Space, Popconfirm } from 'antd';
import { ThunderboltOutlined, ReloadOutlined, CheckCircleOutlined, CloseCircleOutlined, StopOutlined, NodeIndexOutlined } from '@ant-design/icons';
import { submitAlertTriage } from '../../api/task';
import { listAlerts, reviewAlert, analyzeAlert } from '../../api/alert';
import { useTaskPolling } from '../../hooks/useTaskPolling';
import type { Alert, AlertTriageOutcome } from '../../types/api';

import { SEVERITY_TAG_COLORS as SEVERITY_COLORS } from '../../constants/severity';

const { useBreakpoint } = Grid;

function AssessmentBlock({ title, items }: { title: string; items: string[] }) {
  if (!items?.length) return null;
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ fontWeight: 600, marginBottom: 4 }}>{title}</div>
      <ul style={{ margin: 0, paddingLeft: 20, color: '#666' }}>
        {items.map((item) => (
          <li key={item} style={{ marginBottom: 2, wordBreak: 'break-word' }}>
            {item}
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function Alerts() {
  const screens = useBreakpoint();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(false);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [triageResult, setTriageResult] = useState<AlertTriageOutcome | null>(null);
  const [triaging, setTriaging] = useState(false);
  const [triagingAlertId, setTriagingAlertId] = useState<string | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [analyzingAlertId, setAnalyzingAlertId] = useState<string | null>(null);
  const { pollTask } = useTaskPolling();

  const fetchAlerts = useCallback(async (selectedId?: string) => {
    setLoading(true);
    try {
      const resp = await listAlerts({ limit: pageSize, offset: (page - 1) * pageSize });
      setAlerts(resp.alerts);
      setTotal(resp.total);
      if (selectedId) {
        const refreshed = resp.alerts.find((item) => item.id === selectedId);
        if (refreshed) {
          setSelectedAlert(refreshed);
        }
      }
      return resp.alerts;
    } catch {
      message.error('获取告警列表失败');
      return [];
    } finally {
      setLoading(false);
    }
  }, [page, pageSize]);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  const handleTriage = useCallback(async (alert: Alert) => {
    setTriaging(true);
    setTriagingAlertId(alert.id);
    setTriageResult(null);
    setSelectedAlert(alert);
    setDrawerOpen(true);
    try {
      const resp = await submitAlertTriage({
        alert_id: alert.id,
        rule_id: alert.rule_id,
        description: alert.description || '',
        src_ip: alert.src_ip,
      });

      // Sync mode: result returned directly
      if (resp.status === 'completed' && resp.result) {
        setTriageResult(resp.result as unknown as AlertTriageOutcome);
        await fetchAlerts(alert.id);
        message.success('研判完成');
        return;
      }

      // Async mode: poll for result
      const status = await pollTask(resp.task_id, { intervalMs: 1000, maxAttempts: 60 });
      if (status.status === 'SUCCESS' || status.status === 'SUCCEEDED') {
        setTriageResult(status.result as unknown as AlertTriageOutcome);
        await fetchAlerts(alert.id);
        message.success('研判完成');
      } else if (status.status === 'FAILURE' || status.status === 'FAILED') {
        await fetchAlerts(alert.id);
        message.error('研判失败');
      } else if (status.warning) {
        await fetchAlerts(alert.id);
        message.warning(status.warning);
      }
    } catch (err: any) {
      message.error(err.response?.data?.detail || err.message || '研判请求失败');
    } finally {
      setTriaging(false);
      setTriagingAlertId(null);
    }
  }, [fetchAlerts, pollTask]);

  const handleReview = useCallback(async (alertId: string, status: string, verdict?: string) => {
    try {
      await reviewAlert(alertId, { status, verdict });
      message.success(`告警已标记为 ${status}`);
      await fetchAlerts(alertId);
    } catch (err: any) {
      message.error(err.response?.data?.detail || '操作失败');
    }
  }, [fetchAlerts]);

  const handleAnalyze = useCallback(async (alert: Alert) => {
    setAnalyzing(true);
    setAnalyzingAlertId(alert.id);
    try {
      const result = await analyzeAlert(alert.id);
      if (result.success) {
        message.success('协同分析完成');
      } else {
        message.warning('协同分析已启动，但未返回完整结果');
      }
    } catch (err: any) {
      message.error(err.response?.data?.detail || '协同分析失败');
    } finally {
      setAnalyzing(false);
      setAnalyzingAlertId(null);
    }
  }, []);

  const columns = [
    {
      title: '规则',
      dataIndex: 'rule_id',
      key: 'rule_id',
      render: (v: string) => <code>{v}</code>,
    },
    {
      title: '源 IP',
      dataIndex: 'src_ip',
      key: 'src_ip',
      render: (v: string) => v || '-',
    },
    {
      title: '严重程度',
      dataIndex: 'severity',
      key: 'severity',
      render: (v: string) => <Tag color={SEVERITY_COLORS[v] || 'default'}>{v.toUpperCase()}</Tag>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (v: string) => <Tag>{v}</Tag>,
    },
    {
      title: '置信度',
      dataIndex: 'confidence',
      key: 'confidence',
      render: (v: number) => (v != null ? `${(v * 100).toFixed(0)}%` : '-'),
    },
    {
      title: '研判',
      dataIndex: 'verdict',
      key: 'verdict',
      render: (v: string) => v ? <Tag color="purple">{v}</Tag> : '-',
    },
    {
      title: '时间',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (v: string) => new Date(v).toLocaleString('zh-CN'),
    },
    {
      title: '操作',
      key: 'action',
      render: (_: any, record: Alert) => (
        <Space size="small">
          <Tooltip title="提交研判">
            <Button
              type="primary"
              size="small"
              icon={<ThunderboltOutlined />}
              loading={triaging && triagingAlertId === record.id}
              onClick={(e) => {
                e.stopPropagation();
                handleTriage(record);
              }}
            >
              研判
            </Button>
          </Tooltip>
          <Tooltip title="多智能体协同分析">
            <Button
              size="small"
              icon={<NodeIndexOutlined />}
              loading={analyzing && analyzingAlertId === record.id}
              onClick={(e) => {
                e.stopPropagation();
                handleAnalyze(record);
              }}
            >
              协同分析
            </Button>
          </Tooltip>
        </Space>
      ),
    },
  ];

  const handleRowClick = (record: Alert) => {
    setSelectedAlert(record);
    setDrawerOpen(true);
    setTriageResult(null);
  };

  return (
    <div className="page-shell" style={{ flexDirection: 'column' }}>
      <Card
        title="告警管理"
        className="page-card-fill"
        style={{ display: 'flex', flexDirection: 'column' }}
        extra={
          <Button icon={<ReloadOutlined />} onClick={() => void fetchAlerts(selectedAlert?.id)} loading={loading}>
            刷新
          </Button>
        }
      >
        <Table
          dataSource={alerts}
          columns={columns}
          rowKey="id"
          loading={loading}
          onRow={(record) => ({
            onClick: () => handleRowClick(record),
            style: { cursor: 'pointer' },
          })}
          pagination={{
            current: page,
            pageSize,
            total,
            showSizeChanger: true,
            showTotal: (t) => `共 ${t} 条`,
            onChange: (p, ps) => { setPage(p); setPageSize(ps); },
          }}
          size="small"
          scroll={{ x: 900 }}
        />
      </Card>

      <Drawer
        title="告警详情"
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        width={screens.md ? 560 : '100%'}
      >
        {selectedAlert && (
          <>
            {triaging && triagingAlertId === selectedAlert.id && (
              <AntAlert
                type="info"
                showIcon
                style={{ marginBottom: 16 }}
                message="正在研判"
                description="已提交研判任务，结果完成后会自动刷新当前告警并回填到详情页。"
              />
            )}
          <Descriptions column={1} bordered size="small">
              <Descriptions.Item label="ID">{selectedAlert.id}</Descriptions.Item>
              <Descriptions.Item label="规则">
                <code>{selectedAlert.rule_id}</code>
              </Descriptions.Item>
              <Descriptions.Item label="源 IP">{selectedAlert.src_ip || '-'}</Descriptions.Item>
              <Descriptions.Item label="目标 IP">{selectedAlert.dst_ip || '-'}</Descriptions.Item>
              <Descriptions.Item label="严重程度">
                <Tag color={SEVERITY_COLORS[selectedAlert.severity]}>
                  {selectedAlert.severity.toUpperCase()}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="状态">{selectedAlert.status}</Descriptions.Item>
              <Descriptions.Item label="置信度">
                {selectedAlert.confidence != null ? `${(selectedAlert.confidence * 100).toFixed(0)}%` : '-'}
              </Descriptions.Item>
              <Descriptions.Item label="描述">
                <span style={{ wordBreak: 'break-word' }}>{selectedAlert.description || '-'}</span>
              </Descriptions.Item>
              <Descriptions.Item label="时间">
                {new Date(selectedAlert.created_at).toLocaleString('zh-CN')}
              </Descriptions.Item>
            </Descriptions>

            {selectedAlert.asset && (
              <Card title="关联资产" size="small" style={{ marginTop: 16 }}>
                <Descriptions column={1} bordered size="small">
                  <Descriptions.Item label="资产名称">{selectedAlert.asset.name || '-'}</Descriptions.Item>
                  <Descriptions.Item label="类型">{selectedAlert.asset.asset_type || '-'}</Descriptions.Item>
                  <Descriptions.Item label="重要性">
                    <Tag color={selectedAlert.asset.criticality === 'high' ? 'red' : selectedAlert.asset.criticality === 'medium' ? 'orange' : 'green'}>
                      {selectedAlert.asset.criticality || '-'}
                    </Tag>
                  </Descriptions.Item>
                  <Descriptions.Item label="负责人">{selectedAlert.asset.owner || '-'}</Descriptions.Item>
                  <Descriptions.Item label="部门">{selectedAlert.asset.department || '-'}</Descriptions.Item>
                </Descriptions>
              </Card>
            )}

            {selectedAlert.status === 'open' && (
              <Card title="复核操作" size="small" style={{ marginTop: 16 }}>
                <Space wrap>
                  <Popconfirm
                    title="确认此告警为真实威胁？"
                    onConfirm={() => handleReview(selectedAlert.id, 'confirmed', 'true_positive')}
                  >
                    <Button type="primary" icon={<CheckCircleOutlined />} danger>
                      确认为真阳性
                    </Button>
                  </Popconfirm>
                  <Popconfirm
                    title="确认此告警为误报？"
                    onConfirm={() => handleReview(selectedAlert.id, 'false_positive', 'false_positive')}
                  >
                    <Button icon={<CloseCircleOutlined />}>
                      标记为误报
                    </Button>
                  </Popconfirm>
                  <Popconfirm
                    title="关闭此告警？"
                    onConfirm={() => handleReview(selectedAlert.id, 'closed')}
                  >
                    <Button icon={<StopOutlined />}>
                      关闭
                    </Button>
                  </Popconfirm>
                </Space>
              </Card>
            )}

            {triageResult && (
              <Card title="研判结果" size="small" style={{ marginTop: 16 }}>
                <Descriptions column={1} bordered size="small">
                  <Descriptions.Item label="判定">
                    <Tag color={triageResult.verdict === 'true_positive' ? 'red' : 'orange'}>
                      {triageResult.verdict || '-'}
                    </Tag>
                  </Descriptions.Item>
                  <Descriptions.Item label="置信度">
                    {triageResult.confidence != null ? `${(triageResult.confidence * 100).toFixed(0)}%` : '-'}
                  </Descriptions.Item>
                  <Descriptions.Item label="ATT&CK 战术">
                    {triageResult.tactic || '-'}
                  </Descriptions.Item>
                  <Descriptions.Item label="TTP IDs">
                    {triageResult.ttp_ids?.join(', ') || '-'}
                  </Descriptions.Item>
                </Descriptions>
                {triageResult.reasoning && (
                  <p style={{ marginTop: 8, color: '#666', wordBreak: 'break-word' }}>{triageResult.reasoning}</p>
                )}
              </Card>
            )}

            {(triageResult?.assessment || selectedAlert.assessment) && (
              <Card title="研判边界" size="small" style={{ marginTop: 16 }}>
                <AssessmentBlock
                  title="已确认事实"
                  items={triageResult?.assessment?.facts || selectedAlert.assessment?.facts || []}
                />
                <AssessmentBlock
                  title="推断/研判"
                  items={triageResult?.assessment?.inferences || selectedAlert.assessment?.inferences || []}
                />
                <AssessmentBlock
                  title="边界说明"
                  items={triageResult?.assessment?.boundary || selectedAlert.assessment?.boundary || []}
                />
                <Descriptions column={1} bordered size="small" style={{ marginTop: 12 }}>
                  <Descriptions.Item label="置信度">
                    {triageResult?.assessment?.confidence != null
                      ? `${(triageResult.assessment.confidence * 100).toFixed(0)}% (${triageResult.assessment.confidence_label})`
                      : selectedAlert.assessment?.confidence != null
                        ? `${(selectedAlert.assessment.confidence * 100).toFixed(0)}% (${selectedAlert.assessment.confidence_label})`
                        : '-'}
                  </Descriptions.Item>
                  <Descriptions.Item label="证据">
                    {(triageResult?.assessment?.evidence || selectedAlert.assessment?.evidence || []).join(', ') || '-'}
                  </Descriptions.Item>
                </Descriptions>
              </Card>
            )}
          </>
        )}
      </Drawer>
    </div>
  );
}
