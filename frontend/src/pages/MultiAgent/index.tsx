import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ApiOutlined,
  ClockCircleOutlined,
  FileTextOutlined,
  PlayCircleOutlined,
  ReloadOutlined,
  RobotOutlined,
  TeamOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';
import {
  Alert,
  Badge,
  Button,
  Card,
  Col,
  Descriptions,
  Divider,
  Empty,
  Form,
  Input,
  List,
  message,
  Modal,
  Progress,
  Row,
  Select,
  Space,
  Statistic,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import api from '../../api/client';

const { Title, Text, Paragraph } = Typography;

/** 5 种可复用任务模板 — 选择任务类型后自动填充 */
const TASK_TEMPLATES: Record<string, { description: string; target: string; scope: string; params: Record<string, unknown> }> = {
  incident_response: {
    description: '安全事件应急响应：分析日志提取 IoC，查询威胁情报，生成应急报告',
    target: '',
    scope: '内网',
    params: { log_source: 'firewall' },
  },
  penetration_test: {
    description: '目标系统渗透测试：端口扫描 → 服务枚举 → 漏洞扫描 → 攻击面分析 → 报告',
    target: '',
    scope: 'DMZ',
    params: { scan_type: 'full' },
  },
  threat_hunting: {
    description: '主动威胁狩猎：分析流量模式，检测异常行为，关联威胁情报，生成狩猎报告',
    target: '',
    scope: '',
    params: { time_range: '7d' },
  },
  vulnerability_assessment: {
    description: '资产漏洞评估：资产发现 → 漏洞扫描 → 风险评级 → 生成评估报告',
    target: '',
    scope: '',
    params: {},
  },
  malware_analysis: {
    description: '可疑样本分析：静态分析 → 哈希查询 → 行为分析 → 生成分析报告',
    target: '',
    scope: '',
    params: {},
  },
  reverse_engineering: {
    description: '二进制逆向分析：文件结构解析 → 字符串/导入表提取 → 哈希查询 → 行为推断 → 生成分析报告',
    target: '',
    scope: '',
    params: {},
  },
};

interface AgentInfo {
  agent_id: string;
  role: string;
  status: string;
  capabilities: string[];
  load: number;
}

interface SystemStatus {
  status: string;
  agent_stats: {
    total_agents: number;
    by_status: Record<string, number>;
    by_role: Record<string, number>;
    average_load: number;
  };
  agents: AgentInfo[];
}

interface TaskStepResult {
  step_id: number;
  success: boolean;
  agent: string;
  time_ms: number;
  error?: string;
  result: Record<string, unknown>;
}

interface TaskExecutionSnapshot {
  task_id: string;
  task_type: string;
  description: string;
  success: boolean;
  status: string;
  summary: string;
  error?: string;
  execution_time_ms: number;
  total_steps: number;
  successful_steps: number;
  failed_steps: number;
  step_results: TaskStepResult[];
  raw: Record<string, unknown>;
}

interface TaskHistoryItem {
  createdAt: string;
  request: {
    task_type: string;
    description: string;
    priority: string;
    parameters: Record<string, unknown>;
  };
  response: TaskExecutionSnapshot;
}

interface OperationEntry {
  id: number;
  time: string;
  level: 'info' | 'success' | 'warning' | 'error';
  message: string;
}

type RawAgentInfo = Partial<AgentInfo> & Record<string, unknown>;
type RawStats = Partial<SystemStatus['agent_stats']> & Record<string, unknown>;
type RawResponse = {
  status?: unknown;
  agents?: RawAgentInfo[];
  agent_stats?: RawStats;
  stats?: RawStats;
};

type RawTaskResult = Record<string, unknown>;

const ROLE_COLORS: Record<string, string> = {
  coordinator: 'purple',
  planner: 'blue',
  analyzer: 'cyan',
  responder: 'green',
  executor: 'orange',
};

const STATUS_COLORS: Record<string, string> = {
  idle: 'success',
  busy: 'warning',
  error: 'error',
  partial: 'processing',
  completed: 'success',
  failed: 'error',
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function toNumber(value: unknown, fallback = 0): number {
  const num = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function stringifyPreview(value: unknown, fallback = '—'): string {
  if (value === undefined || value === null || value === '') return fallback;
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function normalizeAgent(agent: RawAgentInfo): AgentInfo {
  const capabilities = Array.isArray(agent.capabilities)
    ? agent.capabilities.filter((cap): cap is string => typeof cap === 'string' && cap.trim().length > 0)
    : [];

  return {
    agent_id: String(agent.agent_id ?? ''),
    role: String(agent.role ?? 'unknown'),
    status: String(agent.status ?? 'idle'),
    capabilities,
    load: toNumber(agent.load, 0),
  };
}

function normalizeAgents(rawAgents: RawAgentInfo[] | undefined): AgentInfo[] {
  if (!Array.isArray(rawAgents)) return [];
  return rawAgents.map(normalizeAgent).filter((agent) => agent.agent_id.length > 0);
}

function buildStats(rawStats: RawStats | undefined, agents: AgentInfo[]): SystemStatus['agent_stats'] {
  const byStatus = rawStats?.by_status && typeof rawStats.by_status === 'object'
    ? (rawStats.by_status as Record<string, number>)
    : agents.reduce<Record<string, number>>((acc, agent) => {
        acc[agent.status] = (acc[agent.status] || 0) + 1;
        return acc;
      }, {});

  const byRole = rawStats?.by_role && typeof rawStats.by_role === 'object'
    ? (rawStats.by_role as Record<string, number>)
    : agents.reduce<Record<string, number>>((acc, agent) => {
        acc[agent.role] = (acc[agent.role] || 0) + 1;
        return acc;
      }, {});

  const totalAgents = toNumber(rawStats?.total_agents, agents.length) || agents.length;
  const averageLoad = toNumber(
    rawStats?.average_load,
    agents.length ? agents.reduce((sum, agent) => sum + agent.load, 0) / agents.length : 0,
  );

  return {
    total_agents: totalAgents,
    by_status: byStatus,
    by_role: byRole,
    average_load: averageLoad,
  };
}

function normalizeSystemStatus(payload: RawResponse): SystemStatus {
  const agents = normalizeAgents(payload.agents);
  const stats = buildStats(payload.agent_stats ?? payload.stats, agents);

  return {
    status: String(payload.status ?? 'running'),
    agent_stats: stats,
    agents,
  };
}

function normalizeStepResults(stepResults: unknown): TaskStepResult[] {
  if (!isRecord(stepResults)) return [];

  return Object.entries(stepResults)
    .map(([stepId, raw]) => {
      const payload = isRecord(raw) ? raw : {};
      const result = payload.result;

      return {
        step_id: toNumber(stepId, 0),
        success: Boolean(payload.success),
        agent: String(payload.agent ?? payload.agent_id ?? 'unknown'),
        time_ms: toNumber(payload.time_ms ?? payload.execution_time_ms, 0),
        error: typeof payload.error === 'string' ? payload.error : undefined,
        result: isRecord(result) ? result : { value: result as unknown },
      };
    })
    .sort((a, b) => a.step_id - b.step_id);
}

function normalizeTaskResult(payload: RawTaskResult): TaskExecutionSnapshot {
  const result = isRecord(payload.result) ? payload.result : {};
  const stepResults = normalizeStepResults(result.step_results);
  const totalSteps = toNumber(result.total_steps, stepResults.length) || stepResults.length;
  const successfulSteps = toNumber(
    result.successful_steps,
    stepResults.filter((step) => step.success).length,
  );
  const failedSteps = toNumber(
    result.failed_steps,
    stepResults.filter((step) => !step.success).length,
  );

  return {
    task_id: String(payload.task_id ?? ''),
    task_type: String(result.task_type ?? payload.task_type ?? 'unknown'),
    description: String(result.description ?? payload.description ?? ''),
    success: Boolean(payload.success),
    status: String(result.status ?? (payload.success ? 'completed' : 'failed')),
    summary: String(result.summary ?? ''),
    error: typeof payload.error === 'string' ? payload.error : undefined,
    execution_time_ms: toNumber(payload.execution_time_ms, 0),
    total_steps: totalSteps,
    successful_steps: successfulSteps,
    failed_steps: failedSteps,
    step_results: stepResults,
    raw: payload,
  };
}

function normalizeTaskResponse(values: Record<string, unknown>): TaskHistoryItem {
  const parameters: Record<string, unknown> = {};
  if (typeof values.target === 'string' && values.target.trim()) {
    parameters.target = values.target.trim();
  }
  if (typeof values.content === 'string' && values.content.trim()) {
    parameters.content = values.content.trim();
  }
  if (typeof values.scope === 'string' && values.scope.trim()) {
    parameters.scope = values.scope.trim();
  }

  const parametersJson = typeof values.parameters_json === 'string' ? values.parameters_json.trim() : '';
  if (parametersJson) {
    const parsed = JSON.parse(parametersJson);
    if (Array.isArray(parsed)) {
      parameters.items = parsed;
    } else if (isRecord(parsed)) {
      Object.assign(parameters, parsed);
    } else {
      parameters.value = parsed;
    }
  }

  return {
    createdAt: new Date().toISOString(),
    request: {
      task_type: String(values.task_type ?? 'incident_response'),
      description: String(values.description ?? ''),
      priority: String(values.priority ?? 'medium'),
      parameters,
    },
    response: {
      task_id: '',
      task_type: '',
      description: '',
      success: false,
      status: 'failed',
      summary: '',
      execution_time_ms: 0,
      total_steps: 0,
      successful_steps: 0,
      failed_steps: 0,
      step_results: [],
      raw: {},
    },
  };
}

function formatStepStatus(step: TaskStepResult): { color: 'success' | 'error' | 'processing'; label: string } {
  if (step.success) {
    return { color: 'success', label: '成功' };
  }
  return { color: 'error', label: '失败' };
}

export default function MultiAgent() {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [taskSubmitting, setTaskSubmitting] = useState(false);
  const [taskModalVisible, setTaskModalVisible] = useState(false);
  const [taskHistory, setTaskHistory] = useState<TaskHistoryItem[]>([]);
  const [activeTaskId, setActiveTaskId] = useState<string | null>(null);
  const [operationLog, setOperationLog] = useState<OperationEntry[]>([]);
  const [form] = Form.useForm();

  const appendOperation = useCallback((level: OperationEntry['level'], message: string) => {
    setOperationLog((prev) => [
      ...prev,
      {
        id: prev.length + 1,
        time: new Date().toLocaleTimeString(),
        level,
        message,
      },
    ].slice(-24));
  }, []);

  const fetchStatus = useCallback(async () => {
    setLoading(true);
    appendOperation('info', 'Fetching multi-agent status');
    try {
      const endpoints = ['/multi-agent/agents', '/multi-agent/status'] as const;
      let lastError: unknown = null;

      for (const endpoint of endpoints) {
        try {
          const res = await api.get(endpoint);
          const normalized = normalizeSystemStatus(res.data as RawResponse);
          if (normalized.agents.length > 0 || endpoint === '/multi-agent/status') {
            setStatus(normalized);
            appendOperation(
              'success',
              `Status loaded: ${normalized.agent_stats.total_agents} agents, average load ${(normalized.agent_stats.average_load * 100).toFixed(1)}%`,
            );
            return;
          }
        } catch (error) {
          lastError = error;
        }
      }

      if (lastError) {
        throw lastError;
      }
    } catch (err) {
      console.error('Failed to fetch multi-agent status:', err);
      message.error('获取多智能体状态失败');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    appendOperation('info', 'Multi-agent page initialized');
    fetchStatus();
  }, [appendOperation, fetchStatus]);

  useEffect(() => {
    if (!activeTaskId && taskHistory.length > 0) {
      setActiveTaskId(taskHistory[0].response.task_id);
    }
  }, [activeTaskId, taskHistory]);

  const activeTask = useMemo(
    () => taskHistory.find((item) => item.response.task_id === activeTaskId) ?? taskHistory[0] ?? null,
    [activeTaskId, taskHistory],
  );

  const visibleOperationLog = useMemo(() => [...operationLog].reverse(), [operationLog]);

  const allCapabilities = useMemo(
    () => [...new Set((status?.agents || []).flatMap((agent) => agent.capabilities || []))],
    [status?.agents],
  );

  const agentColumns: ColumnsType<AgentInfo> = [
    {
      title: 'Agent ID',
      dataIndex: 'agent_id',
      key: 'agent_id',
      render: (id: string) => <Tag color="blue">{id}</Tag>,
    },
    {
      title: '角色',
      dataIndex: 'role',
      key: 'role',
      render: (role: string) => (
        <Tag color={ROLE_COLORS[role] || 'default'}>{String(role || 'unknown').toUpperCase()}</Tag>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (agentStatus: string) => (
        <Badge status={(STATUS_COLORS[agentStatus] as any) || 'default'} text={agentStatus || 'unknown'} />
      ),
    },
    {
      title: '负载',
      dataIndex: 'load',
      key: 'load',
      render: (loadValue: number) => {
        const load = Number.isFinite(loadValue) ? loadValue : 0;
        return (
          <Tooltip title={`${(load * 100).toFixed(1)}%`}>
            <Progress
              percent={Math.round(Math.max(0, Math.min(1, load)) * 100)}
              size="small"
              status={load > 0.8 ? 'exception' : load > 0.5 ? 'active' : 'success'}
              showInfo={false}
            />
          </Tooltip>
        );
      },
    },
    {
      title: '能力',
      dataIndex: 'capabilities',
      key: 'capabilities',
      render: (caps?: string[]) => {
        const safeCaps = Array.isArray(caps) ? caps : [];
        return (
          <Space size={[0, 4]} wrap>
            {safeCaps.slice(0, 3).map((cap) => (
              <Tag key={cap}>{cap}</Tag>
            ))}
            {safeCaps.length > 3 && <Tag>+{safeCaps.length - 3}</Tag>}
          </Space>
        );
      },
    },
  ];

  const stepColumns: ColumnsType<TaskStepResult> = [
    {
      title: '步骤',
      dataIndex: 'step_id',
      key: 'step_id',
      width: 88,
      render: (stepId: number) => <Tag color="geekblue">Step {stepId}</Tag>,
    },
    {
      title: 'Agent',
      dataIndex: 'agent',
      key: 'agent',
      render: (agent: string) => <Tag color="blue">{agent}</Tag>,
    },
    {
      title: '状态',
      dataIndex: 'success',
      key: 'success',
      render: (_: boolean, step: TaskStepResult) => {
        const state = formatStepStatus(step);
        return <Badge status={state.color} text={state.label} />;
      },
    },
    {
      title: '耗时',
      dataIndex: 'time_ms',
      key: 'time_ms',
      render: (timeMs: number) => `${Math.max(0, timeMs)} ms`,
    },
    {
      title: '结果摘要',
      dataIndex: 'result',
      key: 'result',
      render: (result: Record<string, unknown>) => {
        const summary =
          stringifyPreview(result.analysis_type) ||
          stringifyPreview(result.action) ||
          stringifyPreview(result.report_type) ||
          stringifyPreview(result.summary) ||
          stringifyPreview(result.status) ||
          '无摘要';
        return <Text>{summary}</Text>;
      },
    },
    {
      title: '错误',
      dataIndex: 'error',
      key: 'error',
      render: (error?: string) => (error ? <Text type="danger">{error}</Text> : <Text type="secondary">-</Text>),
    },
  ];

  const handleCreateTask = async (values: Record<string, unknown>): Promise<boolean> => {
    try {
      setTaskSubmitting(true);
      appendOperation('info', `Submitting ${String(values.task_type ?? 'incident_response')} task`);
      const parameters: Record<string, unknown> = {};

      if (typeof values.target === 'string' && values.target.trim()) {
        parameters.target = values.target.trim();
      }
      if (typeof values.content === 'string' && values.content.trim()) {
        parameters.content = values.content.trim();
      }
      if (typeof values.scope === 'string' && values.scope.trim()) {
        parameters.scope = values.scope.trim();
      }

      const parametersJson = typeof values.parameters_json === 'string' ? values.parameters_json.trim() : '';
      if (parametersJson) {
        const parsed = JSON.parse(parametersJson);
        if (Array.isArray(parsed)) {
          parameters.items = parsed;
        } else if (isRecord(parsed)) {
          Object.assign(parameters, parsed);
        } else {
          parameters.value = parsed;
        }
      }

      const payload = {
        task_type: values.task_type,
        description: values.description,
        priority: values.priority,
        parameters,
      };

      appendOperation('info', 'POST /multi-agent/tasks');
      const res = await api.post('/multi-agent/tasks', payload);
      if (res.data.success) {
        const snapshot = normalizeTaskResult(res.data as RawTaskResult);
        appendOperation(
          'success',
          `Task completed: status=${snapshot.status}, steps=${snapshot.total_steps}, success=${snapshot.successful_steps}`,
        );
        snapshot.step_results.forEach((step) => {
          appendOperation(
            step.success ? 'success' : 'warning',
            `Step ${step.step_id} | ${step.agent} | ${step.success ? 'success' : 'failed'} | ${step.time_ms} ms | ${stringifyPreview(step.result.analysis_type ?? step.result.action ?? step.result.report_type ?? step.result.summary ?? 'N/A')}`,
          );
        });
        const historyItem: TaskHistoryItem = {
          createdAt: new Date().toISOString(),
          request: {
            task_type: String(values.task_type ?? 'incident_response'),
            description: String(values.description ?? ''),
            priority: String(values.priority ?? 'medium'),
            parameters,
          },
          response: snapshot,
        };

        setTaskHistory((prev) => [historyItem, ...prev].slice(0, 8));
        setActiveTaskId(snapshot.task_id);
        message.success(`任务创建成功: ${res.data.task_id}`);
        setTaskModalVisible(false);
        form.resetFields();
        await fetchStatus();
        return true;
      } else {
        message.error(`任务执行失败: ${res.data.error || '未知错误'}`);
        return false;
      }
    } catch (err: any) {
      const errorMsg = err.response?.data?.detail || err.message || '任务创建失败';
      message.error(errorMsg);
      console.error('Task creation error:', err);
      return false;
    } finally {
      setTaskSubmitting(false);
    }
  };

  const activeTaskStepRows = activeTask?.response.step_results ?? [];

  return (
    <div
      style={{
        minHeight: '100%',
        padding: 24,
        background:
          'radial-gradient(circle at top left, var(--app-primary-soft, rgba(24,144,255,0.12)), transparent 28%), radial-gradient(circle at top right, rgba(82,196,26,0.06), transparent 24%), var(--app-bg)',
      }}
    >
      <Card
        style={{
          marginBottom: 24,
          borderRadius: 20,
          border: '1px solid var(--app-primary-soft, rgba(24,144,255,0.12))',
          boxShadow: 'var(--app-shadow)',
        }}
        bodyStyle={{ padding: 24 }}
      >
        <Row gutter={[24, 24]} align="middle">
          <Col xs={24} lg={14}>
            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              <Space align="center" size={12}>
                <div
                  style={{
                    width: 56,
                    height: 56,
                    borderRadius: 16,
                    display: 'grid',
                    placeItems: 'center',
                    background: 'linear-gradient(135deg, #1677ff 0%, #722ed1 100%)',
                    color: '#fff',
                    boxShadow: '0 10px 24px rgba(22, 119, 255, 0.28)',
                  }}
                >
                  <RobotOutlined style={{ fontSize: 26 }} />
                </div>
                <div>
                  <Title level={3} style={{ margin: 0 }}>
                    多智能体协同控制台
                  </Title>
                  <Text type="secondary">
                    观察 Agent 状态、提交任务、查看步骤结果和执行链路。
                  </Text>
                </div>
              </Space>

              <Space wrap>
                <Tag color="geekblue">System: {status?.status || 'running'}</Tag>
                <Tag color="cyan">Agents: {status?.agent_stats?.total_agents ?? 0}</Tag>
                <Tag color="green">Idle: {status?.agent_stats?.by_status?.idle ?? 0}</Tag>
                <Tag color="orange">Busy: {status?.agent_stats?.by_status?.busy ?? 0}</Tag>
                <Tag color="purple">Tasks: {taskHistory.length}</Tag>
              </Space>
            </Space>
          </Col>

          <Col xs={24} lg={10}>
            <Row gutter={12}>
              <Col span={12}>
                <Statistic
                  title="Agent 总数"
                  value={status?.agent_stats?.total_agents ?? 0}
                  prefix={<TeamOutlined />}
                />
              </Col>
              <Col span={12}>
                <Statistic
                  title="平均负载"
                  value={((status?.agent_stats?.average_load ?? 0) * 100).toFixed(1)}
                  suffix="%"
                  prefix={<ThunderboltOutlined />}
                />
              </Col>
            </Row>

            <Space style={{ marginTop: 16 }} wrap>
              <Button icon={<ReloadOutlined />} onClick={fetchStatus} loading={loading}>
                刷新状态
              </Button>
              <Button
                type="primary"
                icon={<PlayCircleOutlined />}
                onClick={() => setTaskModalVisible(true)}
              >
                创建任务
              </Button>
            </Space>
          </Col>
        </Row>
      </Card>

      <Card
        title={
          <Space>
            <ThunderboltOutlined />
            实时操作日志
          </Space>
        }
        extra={<Text type="secondary">{operationLog.length} 条记录</Text>}
        style={{ borderRadius: 18, marginBottom: 16 }}
        bodyStyle={{ paddingTop: 12 }}
      >
        {visibleOperationLog.length > 0 ? (
          <List
            size="small"
            dataSource={visibleOperationLog}
            renderItem={(entry) => {
              const dotColor =
                entry.level === 'success' ? '#52c41a' : entry.level === 'warning' ? '#faad14' : entry.level === 'error' ? '#ff4d4f' : '#1677ff';

              return (
                <List.Item style={{ paddingInline: 0 }}>
                  <Space align="start" size={12} style={{ width: '100%' }}>
                    <span
                      style={{
                        width: 10,
                        height: 10,
                        marginTop: 6,
                        borderRadius: '50%',
                        background: dotColor,
                        flex: '0 0 auto',
                      }}
                    />
                    <Space direction="vertical" size={2} style={{ minWidth: 0, flex: 1 }}>
                      <Space size={8} wrap>
                        <Tag color={entry.level === 'success' ? 'success' : entry.level === 'warning' ? 'warning' : entry.level === 'error' ? 'error' : 'processing'}>
                          {entry.level.toUpperCase()}
                        </Tag>
                        <Text type="secondary">{entry.time}</Text>
                      </Space>
                      <Text style={{ wordBreak: 'break-word' }}>{entry.message}</Text>
                    </Space>
                  </Space>
                </List.Item>
              );
            }}
            style={{ maxHeight: 260, overflowY: 'auto', paddingRight: 8 }}
          />
        ) : (
          <Empty description="页面初始化后，状态刷新和任务提交都会显示在这里" />
        )}
      </Card>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={16}>
          <Card
            title={
              <Space>
                <TeamOutlined />
                Agent 列表
              </Space>
            }
            extra={<Text type="secondary">{status?.agents.length ?? 0} 个已注册 Agent</Text>}
            style={{ borderRadius: 18 }}
          >
            <Table
              columns={agentColumns}
              dataSource={status?.agents ?? []}
              rowKey="agent_id"
              loading={loading}
              pagination={false}
              size="middle"
              locale={{ emptyText: '暂无 Agent 数据' }}
            />
          </Card>

          <Card
            title={
              <Space>
                <ApiOutlined />
                能力雷达
              </Space>
            }
            style={{ marginTop: 16, borderRadius: 18 }}
          >
            {allCapabilities.length > 0 ? (
              <Space size={[0, 8]} wrap>
                {allCapabilities.map((cap) => (
                  <Tag key={cap} icon={<ApiOutlined />} color="blue">
                    {cap}
                  </Tag>
                ))}
              </Space>
            ) : (
              <Empty description="当前没有可用能力标签" />
            )}
          </Card>
        </Col>

        <Col xs={24} xl={8}>
          <Card
            title={
              <Space>
                <ClockCircleOutlined />
                最近任务
              </Space>
            }
            style={{ borderRadius: 18, marginBottom: 16 }}
          >
            {taskHistory.length > 0 ? (
              <List
                dataSource={taskHistory}
                renderItem={(item) => {
                  const selected = item.response.task_id === activeTaskId;
                  const statusTag = item.response.success ? 'success' : 'error';
                  return (
                    <List.Item
                      style={{
                        cursor: 'pointer',
                        borderRadius: 12,
                        padding: 12,
                        background: selected ? 'var(--app-primary-soft, rgba(22,119,255,0.08))' : 'transparent',
                      }}
                      onClick={() => setActiveTaskId(item.response.task_id)}
                    >
                      <Space direction="vertical" size={4} style={{ width: '100%' }}>
                        <Space align="center" style={{ justifyContent: 'space-between', width: '100%' }}>
                          <Tag color={selected ? 'blue' : 'default'}>{item.request.task_type}</Tag>
                          <Badge status={statusTag as any} text={item.response.status} />
                        </Space>
                        <Text strong>{item.request.description || '未填写描述'}</Text>
                        <Text type="secondary" style={{ fontSize: 12 }}>
                          {new Date(item.createdAt).toLocaleString()} · {item.response.total_steps} 步
                        </Text>
                      </Space>
                    </List.Item>
                  );
                }}
              />
            ) : (
              <Empty description="还没有创建任务" />
            )}
          </Card>

          <Card
            title={
              <Space>
                <FileTextOutlined />
                当前任务概览
              </Space>
            }
            style={{ borderRadius: 18 }}
          >
            {activeTask ? (
              <Descriptions column={1} size="small" bordered>
                <Descriptions.Item label="任务 ID">{activeTask.response.task_id || '-'}</Descriptions.Item>
                <Descriptions.Item label="任务类型">{activeTask.response.task_type}</Descriptions.Item>
                <Descriptions.Item label="描述">{activeTask.response.description || '-'}</Descriptions.Item>
                <Descriptions.Item label="执行状态">
                  <Badge
                    status={(STATUS_COLORS[activeTask.response.status] as any) || 'default'}
                    text={activeTask.response.status}
                  />
                </Descriptions.Item>
                <Descriptions.Item label="摘要">
                  {activeTask.response.summary || '暂无摘要'}
                </Descriptions.Item>
                <Descriptions.Item label="耗时">
                  {activeTask.response.execution_time_ms} ms
                </Descriptions.Item>
              </Descriptions>
            ) : (
              <Empty description="选择一个任务后查看详情" />
            )}
          </Card>
        </Col>

        <Col span={24}>
          <Card
            title={
              <Space>
                <ThunderboltOutlined />
                任务执行详情
              </Space>
            }
            style={{ borderRadius: 18 }}
          >
            {activeTask ? (
              <>
                {activeTask.response.error ? (
                  <Alert
                    type="error"
                    showIcon
                    message="任务执行出现错误"
                    description={activeTask.response.error}
                    style={{ marginBottom: 16 }}
                  />
                ) : (
                  <Alert
                    type={activeTask.response.success ? 'success' : 'info'}
                    showIcon
                    message={activeTask.response.summary || '任务执行完成'}
                    description={`共 ${activeTask.response.total_steps} 步，成功 ${activeTask.response.successful_steps} 步，失败 ${activeTask.response.failed_steps} 步。`}
                    style={{ marginBottom: 16 }}
                  />
                )}

                <Table
                  columns={stepColumns}
                  dataSource={activeTaskStepRows}
                  rowKey="step_id"
                  pagination={false}
                  size="middle"
                  locale={{ emptyText: '暂无步骤结果' }}
                />

                <Divider />

                <Paragraph style={{ marginBottom: 8 }}>
                  <Text strong>原始响应</Text>
                </Paragraph>
                <pre
                  style={{
                    margin: 0,
                    padding: 16,
                    borderRadius: 12,
                    background: 'var(--app-code-bg, rgba(0,0,0,0.06))',
                    color: 'var(--app-text, rgba(0,0,0,0.88))',
                    overflowX: 'auto',
                    fontSize: 12,
                    lineHeight: 1.6,
                  }}
                >
                  {JSON.stringify(activeTask.response.raw, null, 2)}
                </pre>
              </>
            ) : (
              <Empty description="创建任务后，这里会显示步骤结果和原始响应" />
            )}
          </Card>
        </Col>
      </Row>

      <Modal
        title="创建多智能体任务"
        open={taskModalVisible}
        onCancel={() => setTaskModalVisible(false)}
        footer={null}
        destroyOnClose
      >
        <Form
          form={form}
          onFinish={handleCreateTask}
          layout="vertical"
          onValuesChange={(changed) => {
            if (changed.task_type) {
              const tpl = TASK_TEMPLATES[changed.task_type];
              if (tpl) {
                form.setFieldsValue({
                  description: tpl.description,
                  target: tpl.target || undefined,
                  scope: tpl.scope || undefined,
                  parameters_json: Object.keys(tpl.params).length ? JSON.stringify(tpl.params, null, 2) : '{}',
                });
              }
            }
          }}
          initialValues={{
            priority: 'medium',
            task_type: 'incident_response',
            parameters_json: '{}',
          }}
        >
          <Form.Item
            name="task_type"
            label="任务类型"
            rules={[{ required: true, message: '请选择任务类型' }]}
          >
            <Select
              placeholder="选择任务类型"
              options={[
                { value: 'incident_response', label: '应急响应' },
                { value: 'penetration_test', label: '渗透测试' },
                { value: 'threat_hunting', label: '威胁狩猎' },
                { value: 'vulnerability_assessment', label: '漏洞评估' },
                { value: 'malware_analysis', label: '恶意软件分析' },
                { value: 'reverse_engineering', label: '逆向工程' },
              ]}
            />
          </Form.Item>

          <Form.Item
            name="description"
            label="任务描述"
            rules={[{ required: true, message: '请输入任务描述' }]}
          >
            <Input.TextArea rows={3} placeholder="例如：调查可疑登录行为并判断是否存在横向移动" />
          </Form.Item>

          <Form.Item name="target" label="目标/对象（可选）">
            <Input placeholder="例如：192.168.1.10 或 production-web-01" />
          </Form.Item>

          <Form.Item name="content" label="文本内容（可选）">
            <Input.TextArea rows={3} placeholder="例如：日志片段、告警内容、IoC 说明..." />
          </Form.Item>

          <Form.Item name="scope" label="作用范围（可选）">
            <Input placeholder="例如：DMZ、内网、单一主机" />
          </Form.Item>

          <Form.Item
            name="parameters_json"
            label="附加参数 JSON（可选）"
            tooltip="会被合并进 parameters 字段，支持直接粘贴 JSON 对象。"
          >
            <Input.TextArea rows={4} placeholder='{"tenant_id":"tenant-a","source":"system"}' />
          </Form.Item>

          <Form.Item
            name="priority"
            label="优先级"
            rules={[{ required: true, message: '请选择优先级' }]}
          >
            <Select
              options={[
                { value: 'critical', label: '紧急' },
                { value: 'high', label: '高' },
                { value: 'medium', label: '中' },
                { value: 'low', label: '低' },
              ]}
            />
          </Form.Item>

          <Form.Item style={{ marginBottom: 0 }}>
            <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
              <Button onClick={() => setTaskModalVisible(false)}>取消</Button>
              <Button type="primary" htmlType="submit" loading={taskSubmitting}>
                提交任务
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
