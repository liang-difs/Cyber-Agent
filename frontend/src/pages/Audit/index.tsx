import { useState, useCallback, useEffect } from 'react';
import { Card, Table, Tag, Select, Space, message, Input, Alert } from 'antd';
import { getAuditLogs } from '../../api/audit';
import type { AuditLog, AuditLogResponse } from '../../types/api';

const ACTION_COLORS: Record<string, string> = {
  read: 'blue',
  create: 'green',
  update: 'orange',
  delete: 'red',
};

const actionOptions = [
  { label: '全部', value: '' },
  { label: 'read', value: 'read' },
  { label: 'create', value: 'create' },
  { label: 'update', value: 'update' },
  { label: 'delete', value: 'delete' },
];

export default function Audit() {
  const [data, setData] = useState<AuditLogResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [action, setAction] = useState('');
  const [userId, setUserId] = useState('');
  const [warning, setWarning] = useState('');

  const fetchData = useCallback(async () => {
    setLoading(true);
    setWarning('');
    try {
      const resp = await getAuditLogs({
        limit: pageSize,
        offset: (page - 1) * pageSize,
        action: action || undefined,
        user_id: userId || undefined,
      });
      setData(resp);
      if (resp.warning) {
        setWarning(resp.warning);
      }
    } catch (err: any) {
      if (err.response?.status === 403) {
        message.error('需要管理员权限');
      } else if (err.response?.status === 500) {
        setWarning('服务器错误，请检查数据库连接');
        setData({ logs: [], total: 0, limit: pageSize, offset: (page - 1) * pageSize });
      } else {
        setWarning('获取审计日志失败，请检查网络连接');
        setData({ logs: [], total: 0, limit: pageSize, offset: (page - 1) * pageSize });
      }
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, action, userId]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const columns = [
    {
      title: '操作',
      dataIndex: 'action',
      key: 'action',
      render: (v: string) => <Tag color={ACTION_COLORS[v] || 'default'}>{v}</Tag>,
    },
    {
      title: '资源',
      dataIndex: 'resource',
      key: 'resource',
      ellipsis: true,
    },
    {
      title: 'IP 地址',
      dataIndex: 'ip_address',
      key: 'ip_address',
      render: (v: string) => v || '-',
    },
    {
      title: '用户 ID',
      dataIndex: 'user_id',
      key: 'user_id',
      render: (v: string) => v ? <code>{v.slice(0, 8)}...</code> : '-',
    },
    {
      title: '状态码',
      key: 'status_code',
      render: (_: any, record: AuditLog) => {
        const code = record.detail?.status_code;
        if (!code) return '-';
        const color = code < 300 ? 'green' : code < 400 ? 'blue' : code < 500 ? 'orange' : 'red';
        return <Tag color={color}>{code}</Tag>;
      },
    },
    {
      title: '耗时',
      key: 'duration',
      render: (_: any, record: AuditLog) => {
        const ms = record.detail?.duration_ms;
        return ms != null ? `${ms}ms` : '-';
      },
    },
    {
      title: '时间',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (v: string) => v ? new Date(v).toLocaleString('zh-CN') : '-',
    },
  ];

  return (
    <div className="page-shell" style={{ flexDirection: 'column' }}>
      <Card title="审计日志" className="page-card-fill">
      {warning && (
        <Alert
          message={warning}
          type="warning"
          showIcon
          closable
          style={{ marginBottom: 16 }}
        />
      )}
      <Space style={{ marginBottom: 16, width: '100%' }} wrap>
        <Select
          value={action}
          onChange={(v) => { setAction(v); setPage(1); }}
          options={actionOptions}
          style={{ width: 140 }}
          placeholder="操作类型"
        />
        <Input.Search
          placeholder="用户 ID"
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
          onSearch={() => { setPage(1); fetchData(); }}
          style={{ width: 'min(100%, 280px)' }}
          allowClear
        />
      </Space>
      <Table
        dataSource={data?.logs || []}
        columns={columns}
        rowKey="id"
        loading={loading}
        pagination={{
          current: page,
          pageSize,
          total: data?.total || 0,
          showSizeChanger: true,
          showTotal: (t) => `共 ${t} 条`,
          onChange: (p, ps) => { setPage(p); setPageSize(ps); },
        }}
        size="small"
        scroll={{ x: 900 }}
        />
      </Card>
    </div>
  );
}
