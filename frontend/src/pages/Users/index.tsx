import { useState, useCallback, useEffect } from 'react';
import { Card, Table, Tag, Button, Drawer, Form, Input, Select, Space, message, Popconfirm, Switch } from 'antd';
import { PlusOutlined, ReloadOutlined, DeleteOutlined, EditOutlined, UserOutlined } from '@ant-design/icons';
import { listUsers, createUser, updateUser, deleteUser } from '../../api/user';
import { useAuthStore } from '../../stores/auth';
import type { User } from '../../types/api';

const ROLE_COLORS: Record<string, string> = {
  admin: 'red',
  analyst: 'blue',
  viewer: 'green',
};

const ROLE_LABELS: Record<string, string> = {
  admin: '管理员',
  analyst: '分析师',
  viewer: '查看者',
};

export default function Users() {
  const currentUser = useAuthStore((s) => s.user);
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(false);
  const [total, setTotal] = useState(0);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [form] = Form.useForm();

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    try {
      const resp = await listUsers({ limit: 100 });
      setUsers(resp.users);
      setTotal(resp.total);
    } catch {
      message.error('获取用户列表失败');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchUsers(); }, [fetchUsers]);

  const handleCreate = () => {
    setEditingUser(null);
    form.resetFields();
    form.setFieldsValue({ role: 'analyst' });
    setDrawerOpen(true);
  };

  const handleEdit = (user: User) => {
    setEditingUser(user);
    form.setFieldsValue({ role: user.role, email: user.email, is_active: user.is_active });
    setDrawerOpen(true);
  };

  const handleSubmit = async () => {
    try {
      const values = await form.validateFields();
      if (editingUser) {
        const body: any = { role: values.role, email: values.email, is_active: values.is_active };
        if (values.password) body.password = values.password;
        await updateUser(editingUser.id, body);
        message.success('用户已更新');
      } else {
        await createUser({
          username: values.username,
          password: values.password,
          role: values.role,
          email: values.email,
        });
        message.success('用户已创建');
      }
      setDrawerOpen(false);
      await fetchUsers();
    } catch (err: any) {
      if (err.response?.data?.detail) message.error(err.response.data.detail);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteUser(id);
      message.success('用户已删除');
      await fetchUsers();
    } catch (err: any) {
      message.error(err.response?.data?.detail || '删除失败');
    }
  };

  const columns = [
    { title: '用户名', dataIndex: 'username', key: 'username' },
    { title: '邮箱', dataIndex: 'email', key: 'email', render: (v: string) => v || '-' },
    {
      title: '角色',
      dataIndex: 'role',
      key: 'role',
      render: (v: string) => <Tag color={ROLE_COLORS[v]}>{ROLE_LABELS[v] || v}</Tag>,
    },
    {
      title: '状态',
      dataIndex: 'is_active',
      key: 'is_active',
      render: (v: boolean) => <Tag color={v ? 'green' : 'default'}>{v ? '活跃' : '停用'}</Tag>,
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (v: string) => (v ? new Date(v).toLocaleString('zh-CN') : '-'),
    },
    {
      title: '操作',
      key: 'action',
      width: 120,
      render: (_: any, record: User) => (
        <Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)} />
          {record.id !== currentUser?.user_id && (
            <Popconfirm title="确认删除此用户？" onConfirm={() => handleDelete(record.id)}>
              <Button size="small" icon={<DeleteOutlined />} danger />
            </Popconfirm>
          )}
        </Space>
      ),
    },
  ];

  return (
    <div className="page-shell" style={{ flexDirection: 'column' }}>
      <Card
        title="用户管理"
        className="page-card-fill"
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={fetchUsers} loading={loading}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>新增用户</Button>
          </Space>
        }
      >
        <Table
          dataSource={users}
          columns={columns}
          rowKey="id"
          loading={loading}
          size="small"
          pagination={false}
        />
      </Card>

      <Drawer
        title={editingUser ? '编辑用户' : '新增用户'}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        width={420}
        extra={
          <Button type="primary" onClick={handleSubmit}>
            {editingUser ? '保存' : '创建'}
          </Button>
        }
      >
        <Form form={form} layout="vertical">
          {!editingUser && (
            <Form.Item label="用户名" name="username" rules={[{ required: true, message: '请输入用户名' }]}>
              <Input prefix={<UserOutlined />} placeholder="如: analyst01" />
            </Form.Item>
          )}
          <Form.Item label="角色" name="role" rules={[{ required: true }]}>
            <Select
              options={[
                { value: 'admin', label: '管理员 — 全部权限' },
                { value: 'analyst', label: '分析师 — 对话+工具+研判+报告' },
                { value: 'viewer', label: '查看者 — 只读访问' },
              ]}
            />
          </Form.Item>
          <Form.Item label="邮箱" name="email">
            <Input placeholder="user@example.com" />
          </Form.Item>
          <Form.Item
            label={editingUser ? '新密码（留空不修改）' : '密码'}
            name="password"
            rules={editingUser ? [] : [{ required: true, message: '请输入密码' }, { min: 8, message: '至少 8 个字符' }]}
          >
            <Input.Password placeholder="至少 8 个字符" />
          </Form.Item>
          {editingUser && (
            <Form.Item label="账号状态" name="is_active" valuePropName="checked">
              <Switch checkedChildren="活跃" unCheckedChildren="停用" />
            </Form.Item>
          )}
        </Form>
      </Drawer>
    </div>
  );
}
