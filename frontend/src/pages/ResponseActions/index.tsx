import { useState, useEffect, useCallback } from 'react';
import {
  Card, Row, Col, Table, Tag, Button, Space, Statistic, Modal, Form,
  Input, Select, message, Descriptions, Timeline, Alert, Tooltip, Typography,
} from 'antd';
import {
  ThunderboltOutlined, ReloadOutlined, PlayCircleOutlined,
  CheckCircleOutlined, CloseCircleOutlined, HistoryOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import api from '../../api/client';

const { Text } = Typography;

interface ActionRecord {
  action_id: string;
  action_type: string;
  status: string;
  success: boolean;
  message: string;
  executed_at: string;
  params: Record<string, any>;
}

interface ActionStats {
  total_actions: number;
  successful: number;
  failed: number;
  success_rate: number;
  by_type: Record<string, number>;
  pending_rollbacks: number;
}

const ACTION_TYPE_LABELS: Record<string, string> = {
  block_ip: '阻断IP',
  isolate_host: '隔离主机',
  notify: '发送通知',
  quarantine_file: '隔离文件',
  disable_account: '禁用账户',
};

const ACTION_TYPE_COLORS: Record<string, string> = {
  block_ip: 'red',
  isolate_host: 'orange',
  notify: 'blue',
  quarantine_file: 'purple',
  disable_account: 'volcano',
};

const STATUS_COLORS: Record<string, string> = {
  success: 'success',
  failed: 'error',
  pending: 'processing',
  executing: 'warning',
  rolled_back: 'default',
};

export default function ResponseActions() {
  const [stats, setStats] = useState<ActionStats | null>(null);
  const [history, setHistory] = useState<ActionRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [actionModalVisible, setActionModalVisible] = useState(false);
  const [form] = Form.useForm();

  const fetchStats = useCallback(async () => {
    setLoading(true);
    try {
      const [statsRes, historyRes] = await Promise.all([
        api.get('/response-actions/stats'),
        api.get('/response-actions/history'),
      ]);
      setStats(statsRes.data);
      setHistory(historyRes.data.history || []);
    } catch (err) {
      console.error('Failed to fetch action stats:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  const handleExecuteAction = async (values: any) => {
    try {
      const params = values.params ? JSON.parse(values.params) : {};
      const res = await api.post('/response-actions/execute', {
        action_type: values.action_type,
        params,
      });
      if (res.data.success) {
        message.success(res.data.message || '动作执行成功');
        setActionModalVisible(false);
        form.resetFields();
        fetchStats();
      } else {
        message.error(res.data.message || '动作执行失败');
      }
    } catch (err) {
      message.error('动作执行失败');
    }
  };

  const historyColumns: ColumnsType<ActionRecord> = [
    {
      title: '动作ID',
      dataIndex: 'action_id',
      key: 'action_id',
      ellipsis: true,
      render: (id: string) => (
        <Tooltip title={id}>
          <Tag>{id?.substring(0, 8)}...</Tag>
        </Tooltip>
      ),
    },
    {
      title: '动作类型',
      dataIndex: 'action_type',
      key: 'action_type',
      render: (type: string) => (
        <Tag color={ACTION_TYPE_COLORS[type] || 'default'}>
          {ACTION_TYPE_LABELS[type] || type}
        </Tag>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (status: string) => (
        <Tag color={STATUS_COLORS[status] || 'default'}>
          {status}
        </Tag>
      ),
    },
    {
      title: '结果',
      dataIndex: 'success',
      key: 'success',
      render: (success: boolean) => (
        success ? (
          <CheckCircleOutlined style={{ color: '#52c41a', fontSize: 18 }} />
        ) : (
          <CloseCircleOutlined style={{ color: '#ff4d4f', fontSize: 18 }} />
        )
      ),
    },
    {
      title: '消息',
      dataIndex: 'message',
      key: 'message',
      ellipsis: true,
    },
    {
      title: '执行时间',
      dataIndex: 'executed_at',
      key: 'executed_at',
      render: (time: string) => time ? new Date(time).toLocaleString('zh-CN') : '-',
    },
  ];

  return (
    <div style={{ padding: 24 }}>
      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card
            title={
              <Space>
                <ThunderboltOutlined />
                响应动作管理
              </Space>
            }
            extra={
              <Space>
                <Button icon={<ReloadOutlined />} onClick={fetchStats}>
                  刷新
                </Button>
                <Button
                  type="primary"
                  icon={<PlayCircleOutlined />}
                  onClick={() => setActionModalVisible(true)}
                >
                  执行动作
                </Button>
              </Space>
            }
          >
            <Row gutter={16}>
              <Col span={6}>
                <Statistic
                  title="总执行次数"
                  value={stats?.total_actions || 0}
                  prefix={<HistoryOutlined />}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="成功次数"
                  value={stats?.successful || 0}
                  valueStyle={{ color: '#52c41a' }}
                  prefix={<CheckCircleOutlined />}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="失败次数"
                  value={stats?.failed || 0}
                  valueStyle={{ color: '#ff4d4f' }}
                  prefix={<CloseCircleOutlined />}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="成功率"
                  value={((stats?.success_rate || 0) * 100).toFixed(1)}
                  suffix="%"
                  valueStyle={{ color: (stats?.success_rate || 0) > 0.8 ? '#52c41a' : '#faad14' }}
                />
              </Col>
            </Row>
          </Card>
        </Col>

        <Col span={24}>
          <Card
            title="执行历史"
            extra={
              <Space>
                {stats?.pending_rollbacks ? (
                  <Alert
                    message={`${stats.pending_rollbacks} 个动作可回滚`}
                    type="warning"
                    showIcon
                  />
                ) : null}
              </Space>
            }
          >
            <Table
              columns={historyColumns}
              dataSource={history}
              rowKey="action_id"
              loading={loading}
              pagination={{ pageSize: 10 }}
            />
          </Card>
        </Col>

        <Col span={12}>
          <Card title="按动作类型分布">
            <Descriptions column={1}>
              {Object.entries(stats?.by_type || {}).map(([type, count]) => (
                <Descriptions.Item key={type} label={
                  <Tag color={ACTION_TYPE_COLORS[type] || 'default'}>
                    {ACTION_TYPE_LABELS[type] || type}
                  </Tag>
                }>
                  {count} 次
                </Descriptions.Item>
              ))}
            </Descriptions>
          </Card>
        </Col>

        <Col span={12}>
          <Card title="可用动作类型">
            <Timeline
              items={[
                {
                  color: 'red',
                  children: (
                    <div>
                      <Tag color="red">block_ip</Tag>
                      <Text type="secondary">阻断指定IP地址的网络访问</Text>
                    </div>
                  ),
                },
                {
                  color: 'orange',
                  children: (
                    <div>
                      <Tag color="orange">isolate_host</Tag>
                      <Text type="secondary">隔离受感染的主机</Text>
                    </div>
                  ),
                },
                {
                  color: 'blue',
                  children: (
                    <div>
                      <Tag color="blue">notify</Tag>
                      <Text type="secondary">发送安全事件通知</Text>
                    </div>
                  ),
                },
                {
                  color: 'purple',
                  children: (
                    <div>
                      <Tag color="purple">quarantine_file</Tag>
                      <Text type="secondary">隔离可疑或恶意文件</Text>
                    </div>
                  ),
                },
                {
                  color: 'volcano',
                  children: (
                    <div>
                      <Tag color="volcano">disable_account</Tag>
                      <Text type="secondary">禁用被入侵的用户账户</Text>
                    </div>
                  ),
                },
              ]}
            />
          </Card>
        </Col>
      </Row>

      <Modal
        title="执行响应动作"
        open={actionModalVisible}
        onCancel={() => setActionModalVisible(false)}
        footer={null}
      >
        <Form form={form} onFinish={handleExecuteAction} layout="vertical">
          <Form.Item name="action_type" label="动作类型" rules={[{ required: true }]}>
            <Select placeholder="选择动作类型">
              <Select.Option value="block_ip">阻断IP</Select.Option>
              <Select.Option value="isolate_host">隔离主机</Select.Option>
              <Select.Option value="notify">发送通知</Select.Option>
              <Select.Option value="quarantine_file">隔离文件</Select.Option>
              <Select.Option value="disable_account">禁用账户</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item name="params" label="参数 (JSON格式)">
            <Input.TextArea
              rows={5}
              placeholder={`例如（阻断IP）：\n{\n  "ip": "192.168.1.100",\n  "duration_seconds": 3600,\n  "reason": "检测到恶意活动"\n}`}
            />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" block>
              执行动作
            </Button>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
