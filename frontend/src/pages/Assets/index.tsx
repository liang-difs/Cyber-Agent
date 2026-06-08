import { useState, useCallback, useEffect } from 'react';
import { Card, Table, Tag, Button, Drawer, Form, Input, Select, Space, message, Popconfirm, Descriptions, Grid } from 'antd';
import { PlusOutlined, ReloadOutlined, DeleteOutlined, EditOutlined } from '@ant-design/icons';
import { listAssets, createAsset, updateAsset, deleteAsset } from '../../api/asset';
import { SEVERITY_TAG_COLORS } from '../../constants/severity';
import type { Asset } from '../../types/api';

const { useBreakpoint } = Grid;

const ASSET_TYPES = [
  { value: 'host', label: '主机' },
  { value: 'server', label: '服务器' },
  { value: 'network', label: '网络设备' },
  { value: 'application', label: '应用' },
];

const CRITICALITY_OPTIONS = [
  { value: 'critical', label: '关键' },
  { value: 'high', label: '高' },
  { value: 'medium', label: '中' },
  { value: 'low', label: '低' },
];

const STATUS_OPTIONS = [
  { value: 'active', label: '活跃' },
  { value: 'inactive', label: '停用' },
  { value: 'decommissioned', label: '已下线' },
];

export default function Assets() {
  const screens = useBreakpoint();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(false);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editingAsset, setEditingAsset] = useState<Asset | null>(null);
  const [form] = Form.useForm();

  const fetchAssets = useCallback(async () => {
    setLoading(true);
    try {
      const resp = await listAssets({ limit: pageSize, offset: (page - 1) * pageSize });
      setAssets(resp.assets);
      setTotal(resp.total);
    } catch {
      message.error('获取资产列表失败');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize]);

  useEffect(() => { fetchAssets(); }, [fetchAssets]);

  const handleCreate = () => {
    setEditingAsset(null);
    form.resetFields();
    setDrawerOpen(true);
  };

  const handleEdit = (asset: Asset) => {
    setEditingAsset(asset);
    form.setFieldsValue(asset);
    setDrawerOpen(true);
  };

  const handleSubmit = async () => {
    try {
      const values = await form.validateFields();
      if (editingAsset) {
        await updateAsset(editingAsset.id, values);
        message.success('资产已更新');
      } else {
        await createAsset(values);
        message.success('资产已创建');
      }
      setDrawerOpen(false);
      await fetchAssets();
    } catch (err: any) {
      if (err.response?.data?.detail) message.error(err.response.data.detail);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteAsset(id);
      message.success('资产已删除');
      await fetchAssets();
    } catch {
      message.error('删除失败');
    }
  };

  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name', ellipsis: true },
    { title: '类型', dataIndex: 'asset_type', key: 'type', width: 100, render: (v: string) => ASSET_TYPES.find(t => t.value === v)?.label || v },
    { title: 'IP', dataIndex: 'ip_address', key: 'ip', width: 140, render: (v: string) => v || '-' },
    { title: '负责人', dataIndex: 'owner', key: 'owner', width: 100, render: (v: string) => v || '-' },
    {
      title: '重要性',
      dataIndex: 'criticality',
      key: 'criticality',
      width: 90,
      render: (v: string) => <Tag color={SEVERITY_TAG_COLORS[v] || 'default'}>{v?.toUpperCase()}</Tag>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 80,
      render: (v: string) => <Tag color={v === 'active' ? 'green' : v === 'inactive' ? 'orange' : 'default'}>{STATUS_OPTIONS.find(s => s.value === v)?.label || v}</Tag>,
    },
    {
      title: '操作',
      key: 'action',
      width: 120,
      render: (_: any, record: Asset) => (
        <Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)} />
          <Popconfirm title="确认删除此资产？" onConfirm={() => handleDelete(record.id)}>
            <Button size="small" icon={<DeleteOutlined />} danger />
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <div className="page-shell" style={{ flexDirection: 'column' }}>
      <Card
        title="资产管理"
        className="page-card-fill"
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={fetchAssets} loading={loading}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>新增资产</Button>
          </Space>
        }
      >
        <Table
          dataSource={assets}
          columns={columns}
          rowKey="id"
          loading={loading}
          size="small"
          scroll={{ x: 800 }}
          pagination={{
            current: page,
            pageSize,
            total,
            showSizeChanger: true,
            showTotal: (t) => `共 ${t} 条`,
            onChange: (p, ps) => { setPage(p); setPageSize(ps); },
          }}
        />
      </Card>

      <Drawer
        title={editingAsset ? '编辑资产' : '新增资产'}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        width={screens.md ? 520 : '100%'}
        extra={
          <Button type="primary" onClick={handleSubmit}>
            {editingAsset ? '保存' : '创建'}
          </Button>
        }
      >
        <Form form={form} layout="vertical">
          <Form.Item label="名称" name="name" rules={[{ required: true, message: '请输入资产名称' }]}>
            <Input placeholder="如: Web Server 01" />
          </Form.Item>
          <Form.Item label="类型" name="asset_type" initialValue="host">
            <Select options={ASSET_TYPES} />
          </Form.Item>
          <Form.Item label="IP 地址" name="ip_address">
            <Input placeholder="192.168.1.100" />
          </Form.Item>
          <Form.Item label="主机名" name="hostname">
            <Input placeholder="web-server-01.local" />
          </Form.Item>
          <Form.Item label="操作系统" name="os">
            <Input placeholder="Ubuntu 22.04" />
          </Form.Item>
          <Form.Item label="负责人" name="owner">
            <Input placeholder="张三" />
          </Form.Item>
          <Form.Item label="部门" name="department">
            <Input placeholder="安全运维" />
          </Form.Item>
          <Form.Item label="重要性" name="criticality" initialValue="medium">
            <Select options={CRITICALITY_OPTIONS} />
          </Form.Item>
          <Form.Item label="备注" name="notes">
            <Input.TextArea rows={3} placeholder="可选备注信息" />
          </Form.Item>
        </Form>
      </Drawer>
    </div>
  );
}
