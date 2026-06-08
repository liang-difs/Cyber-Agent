import { useState, useEffect, useCallback } from 'react';
import {
  Card, Row, Col, Table, Tag, Button, Space, Statistic, Modal, Form,
  Input, Select, message, Tabs, Descriptions, Alert,
} from 'antd';
import {
  SafetyCertificateOutlined, ReloadOutlined,
  FileSearchOutlined, BugOutlined, SafetyOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import api from '../../api/client';

interface RuleInfo {
  id?: string;
  name?: string;
  title?: string;
  level?: string;
  severity?: string;
  status?: string;
  tags?: string[] | string;
  namespace?: string;
  meta?: {
    description?: string;
    severity?: string;
    confidence?: string;
    author?: string;
  };
}

interface RuleStats {
  sigma: {
    total_rules: number;
    by_level: Record<string, number>;
    by_tag: Record<string, string[]>;
  };
  yara: {
    total_rules: number;
    yara_available: boolean;
    compiled: boolean;
  };
  total_rules: number;
}

interface MatchResult {
  rule_type: string;
  rule_name: string;
  rule_id: string;
  description: string;
  severity: string;
  confidence: number;
  matched_conditions: string[];
  recommendations: string[];
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ff4d4f',
  high: '#fa8c16',
  medium: '#faad14',
  low: '#52c41a',
  informational: '#1890ff',
};

export default function RuleEngine() {
  const [stats, setStats] = useState<RuleStats | null>(null);
  const [sigmaRules, setSigmaRules] = useState<RuleInfo[]>([]);
  const [yaraRules, setYaraRules] = useState<RuleInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [matchModalVisible, setMatchModalVisible] = useState(false);
  const [matchResults, setMatchResults] = useState<MatchResult[]>([]);
  const [matchSummary, setMatchSummary] = useState('');
  const [form] = Form.useForm();

  const fetchStats = useCallback(async () => {
    setLoading(true);
    try {
      const [statsRes, sigmaRes, yaraRes] = await Promise.all([
        api.get('/rules/stats'),
        api.get('/rules/sigma/rules'),
        api.get('/rules/yara/rules'),
      ]);
      setStats(statsRes.data);
      setSigmaRules(sigmaRes.data.rules || []);
      setYaraRules(yaraRes.data.rules || []);
    } catch (err) {
      console.error('Failed to fetch rule stats:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  const handleMatch = async (values: any) => {
    try {
      const res = await api.post('/rules/match', {
        match_type: values.match_type,
        content: values.content,
        file_path: values.match_type === 'file' ? values.content : undefined,
      });
      if (res.data.success) {
        setMatchResults(res.data.matches || []);
        setMatchSummary(res.data.summary || '');
        message.success(res.data.summary);
      } else {
        message.error('匹配失败');
      }
    } catch (err) {
      message.error('规则匹配失败');
    }
  };

  const sigmaColumns: ColumnsType<RuleInfo> = [
    {
      title: '规则ID',
      dataIndex: 'id',
      key: 'id',
      width: 120,
      render: (id: string) => {
        // 将 UUID 格式转为友好显示：取最后段或序号
        if (!id) return '-';
        const match = id.match(/([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})/);
        if (match) {
          // 提取序号部分（最后12位转十进制）
          const seq = parseInt(match[5], 16);
          return <Tag color="blue">SIGMA-{String(seq).padStart(3, '0')}</Tag>;
        }
        return <Tag color="blue">{id}</Tag>;
      },
    },
    {
      title: '标题',
      dataIndex: 'title',
      key: 'title',
      ellipsis: true,
    },
    {
      title: '级别',
      dataIndex: 'level',
      key: 'level',
      width: 90,
      render: (level: string) => (
        <Tag color={SEVERITY_COLORS[level] || 'default'}>
          {level?.toUpperCase()}
        </Tag>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (status: string) => (
        <Tag color={status === 'stable' ? 'green' : 'orange'}>
          {status}
        </Tag>
      ),
    },
    {
      title: '标签',
      dataIndex: 'tags',
      key: 'tags',
      render: (tags: string[] | string) => {
        const tagList = Array.isArray(tags) ? tags : (tags ? tags.split(',').map(t => t.trim()) : []);
        return (
          <Space size={[0, 4]} wrap>
            {tagList.slice(0, 2).map((tag) => (
              <Tag key={tag}>{tag}</Tag>
            ))}
          </Space>
        );
      },
    },
  ];

  const yaraColumns: ColumnsType<RuleInfo> = [
    {
      title: '规则名',
      dataIndex: 'name',
      key: 'name',
      render: (name: string) => <Tag color="purple">{name}</Tag>,
    },
    {
      title: '描述',
      key: 'description',
      ellipsis: true,
      render: (_: any, record: RuleInfo) => record.meta?.description || '-',
    },
    {
      title: '级别',
      key: 'severity',
      width: 90,
      render: (_: any, record: RuleInfo) => {
        const level = record.meta?.severity || 'medium';
        return (
          <Tag color={SEVERITY_COLORS[level] || 'default'}>
            {level.toUpperCase()}
          </Tag>
        );
      },
    },
    {
      title: '命名空间',
      dataIndex: 'namespace',
      key: 'namespace',
      width: 100,
      render: (ns: string) => <Tag>{ns || 'default'}</Tag>,
    },
    {
      title: '标签',
      dataIndex: 'tags',
      key: 'tags',
      render: (tags: string[] | string) => {
        const tagList = Array.isArray(tags) ? tags : (tags ? tags.split(',').map(t => t.trim()) : []);
        return (
          <Space size={[0, 4]} wrap>
            {tagList.slice(0, 3).map((tag) => (
              <Tag key={tag}>{tag}</Tag>
            ))}
          </Space>
        );
      },
    },
  ];

  const matchColumns: ColumnsType<MatchResult> = [
    {
      title: '规则类型',
      dataIndex: 'rule_type',
      key: 'rule_type',
      render: (type: string) => (
        <Tag color={type === 'sigma' ? 'blue' : 'purple'}>
          {type?.toUpperCase()}
        </Tag>
      ),
    },
    {
      title: '规则名称',
      dataIndex: 'rule_name',
      key: 'rule_name',
      ellipsis: true,
    },
    {
      title: '严重等级',
      dataIndex: 'severity',
      key: 'severity',
      render: (severity: string) => (
        <Tag color={SEVERITY_COLORS[severity] || 'default'}>
          {severity?.toUpperCase()}
        </Tag>
      ),
    },
    {
      title: '置信度',
      dataIndex: 'confidence',
      key: 'confidence',
      render: (conf: number) => `${((conf || 0) * 100).toFixed(0)}%`,
    },
    {
      title: '匹配条件',
      dataIndex: 'matched_conditions',
      key: 'matched_conditions',
      render: (conditions: string[]) => (
        <Space size={[0, 4]} wrap>
          {conditions?.map((c) => (
            <Tag key={c}>{c}</Tag>
          ))}
        </Space>
      ),
    },
    {
      title: '建议',
      dataIndex: 'recommendations',
      key: 'recommendations',
      ellipsis: true,
      render: (recs: string[]) => recs?.[0] || '-',
    },
  ];

  return (
    <div style={{ padding: 24 }}>
      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card
            title={
              <Space>
                <SafetyCertificateOutlined />
                Sigma/YARA 规则引擎
              </Space>
            }
            extra={
              <Space>
                <Button icon={<ReloadOutlined />} onClick={fetchStats}>
                  刷新
                </Button>
                <Button
                  type="primary"
                  icon={<FileSearchOutlined />}
                  onClick={() => setMatchModalVisible(true)}
                >
                  规则匹配
                </Button>
              </Space>
            }
          >
            <Row gutter={16}>
              <Col span={6}>
                <Statistic
                  title="规则总数"
                  value={stats?.total_rules || 0}
                  prefix={<SafetyOutlined />}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="Sigma 规则"
                  value={stats?.sigma?.total_rules || 0}
                  valueStyle={{ color: '#1890ff' }}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="YARA 规则"
                  value={stats?.yara?.total_rules || 0}
                  valueStyle={{ color: '#722ed1' }}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="YARA 状态"
                  value={stats?.yara?.yara_available ? '可用' : '不可用'}
                  valueStyle={{ color: stats?.yara?.yara_available ? '#52c41a' : '#ff4d4f' }}
                />
              </Col>
            </Row>
          </Card>
        </Col>

        <Col span={24}>
          <Card title="规则列表">
            <Tabs
              items={[
                {
                  key: 'sigma',
                  label: `Sigma 规则 (${stats?.sigma?.total_rules || 0})`,
                  children: (
                    <Table
                      columns={sigmaColumns}
                      dataSource={sigmaRules}
                      rowKey="id"
                      loading={loading}
                      pagination={{ pageSize: 10 }}
                    />
                  ),
                },
                {
                  key: 'yara',
                  label: `YARA 规则 (${stats?.yara?.total_rules || 0})`,
                  children: (
                    <Table
                      columns={yaraColumns}
                      dataSource={yaraRules}
                      rowKey="name"
                      loading={loading}
                      pagination={{ pageSize: 10 }}
                    />
                  ),
                },
              ]}
            />
          </Card>
        </Col>

        <Col span={12}>
          <Card title="按级别分布">
            <Descriptions column={1}>
              {Object.entries(stats?.sigma?.by_level || {}).map(([level, count]) => (
                <Descriptions.Item key={level} label={
                  <Tag color={SEVERITY_COLORS[level] || 'default'}>{level}</Tag>
                }>
                  {count} 条
                </Descriptions.Item>
              ))}
            </Descriptions>
          </Card>
        </Col>

        <Col span={12}>
          <Card title="按标签分布">
            <Space size={[0, 8]} wrap>
              {Object.keys(stats?.sigma?.by_tag || {}).map((tag) => (
                <Tag key={tag} icon={<BugOutlined />}>
                  {tag} ({stats?.sigma?.by_tag[tag]?.length || 0})
                </Tag>
              ))}
            </Space>
          </Card>
        </Col>
      </Row>

      <Modal
        title="规则匹配"
        open={matchModalVisible}
        onCancel={() => {
          setMatchModalVisible(false);
          setMatchResults([]);
          setMatchSummary('');
        }}
        footer={null}
        width={800}
      >
        <Form form={form} onFinish={handleMatch} layout="vertical">
          <Form.Item name="match_type" label="匹配类型" rules={[{ required: true }]}>
            <Select placeholder="选择匹配类型">
              <Select.Option value="log">日志匹配 (Sigma)</Select.Option>
              <Select.Option value="file">文件匹配 (YARA)</Select.Option>
              <Select.Option value="data">数据匹配 (YARA)</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item name="content" label="内容" rules={[{ required: true }]}>
            <Input.TextArea rows={5} placeholder="输入日志内容、文件路径或数据..." />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" block>
              执行匹配
            </Button>
          </Form.Item>
        </Form>

        {matchSummary && (
          <Alert message={matchSummary} type="info" showIcon style={{ marginTop: 16 }} />
        )}

        {matchResults.length > 0 && (
          <Card title="匹配结果" style={{ marginTop: 16 }}>
            <Table
              columns={matchColumns}
              dataSource={matchResults}
              rowKey="rule_id"
              pagination={false}
              size="small"
            />
          </Card>
        )}
      </Modal>
    </div>
  );
}
