import { useState, useEffect, useCallback } from 'react';
import {
  Card, Row, Col, Table, Tag, Button, Space, Statistic, Modal, Form,
  Input, Select, message, Descriptions, Tabs, List, Typography, Tooltip,
} from 'antd';
import {
  NodeIndexOutlined, SearchOutlined, ReloadOutlined,
  ApartmentOutlined, BugOutlined, GlobalOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import api from '../../api/client';

const { Text, Paragraph } = Typography;

interface Entity {
  id: string;
  name: string;
  entity_type: string;
  properties: Record<string, any>;
  aliases: string[];
  source: string;
  confidence: number;
  tags: string[];
}

interface Relation {
  id: string;
  source_id: string;
  target_id: string;
  relation_type: string;
  properties: Record<string, any>;
  confidence: number;
}

interface GraphStats {
  total_entities: number;
  total_relations: number;
  entity_types: Record<string, number>;
  relation_types: Record<string, number>;
}

const ENTITY_TYPE_COLORS: Record<string, string> = {
  cve: 'red',
  malware: 'purple',
  threat_actor: 'volcano',
  technique: 'blue',
  ip: 'cyan',
  domain: 'green',
  hash: 'orange',
  url: 'geekblue',
  asset: 'gold',
};

const ENTITY_TYPE_ICONS: Record<string, React.ReactNode> = {
  cve: <BugOutlined />,
  malware: <BugOutlined />,
  ip: <GlobalOutlined />,
  domain: <GlobalOutlined />,
};

export default function KnowledgeGraph() {
  const [stats, setStats] = useState<GraphStats | null>(null);
  const [entities, setEntities] = useState<Entity[]>([]);
  const [selectedEntity, setSelectedEntity] = useState<Entity | null>(null);
  const [neighbors, setNeighbors] = useState<{ entities: Entity[], relations: Relation[] }>({ entities: [], relations: [] });
  const [loading, setLoading] = useState(false);
  const [searchModalVisible, setSearchModalVisible] = useState(false);
  const [form] = Form.useForm();

  const fetchStats = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.post('/agent/chat', {
        message: '使用knowledge_graph工具获取统计信息，operation=stats',
      });
      if (res.data?.statistics) {
        setStats(res.data.statistics);
      }
    } catch (err) {
      console.error('Failed to fetch graph stats:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  const handleSearch = async (values: any) => {
    try {
      const res = await api.post('/agent/chat', {
        message: `使用knowledge_graph工具搜索实体，operation=search，query=${values.query}，entity_type=${values.entity_type || ''}`,
      });
      if (res.data?.entities) {
        setEntities(res.data.entities);
      }
    } catch (err) {
      message.error('搜索失败');
    }
  };

  const handleEntityClick = async (entity: Entity) => {
    setSelectedEntity(entity);
    try {
      const res = await api.post('/agent/chat', {
        message: `使用knowledge_graph工具查询实体关系，operation=query，entity_id=${entity.id}，depth=1`,
      });
      if (res.data?.neighbors) {
        setNeighbors(res.data.neighbors);
      }
    } catch (err) {
      console.error('Failed to fetch neighbors:', err);
    }
  };

  const entityColumns: ColumnsType<Entity> = [
    {
      title: '名称',
      dataIndex: 'name',
      key: 'name',
      render: (name: string, record: Entity) => (
        <Button type="link" onClick={() => handleEntityClick(record)}>
          {name}
        </Button>
      ),
    },
    {
      title: '类型',
      dataIndex: 'entity_type',
      key: 'entity_type',
      render: (type: string) => (
        <Tag color={ENTITY_TYPE_COLORS[type] || 'default'} icon={ENTITY_TYPE_ICONS[type]}>
          {type.toUpperCase()}
        </Tag>
      ),
    },
    {
      title: '置信度',
      dataIndex: 'confidence',
      key: 'confidence',
      render: (conf: number) => `${(conf * 100).toFixed(0)}%`,
    },
    {
      title: '来源',
      dataIndex: 'source',
      key: 'source',
      ellipsis: true,
    },
    {
      title: '标签',
      dataIndex: 'tags',
      key: 'tags',
      render: (tags: string[]) => (
        <Space size={[0, 4]} wrap>
          {tags?.slice(0, 3).map((tag) => (
            <Tag key={tag}>{tag}</Tag>
          ))}
        </Space>
      ),
    },
  ];

  const neighborColumns: ColumnsType<Entity> = [
    {
      title: '名称',
      dataIndex: 'name',
      key: 'name',
    },
    {
      title: '类型',
      dataIndex: 'entity_type',
      key: 'entity_type',
      render: (type: string) => (
        <Tag color={ENTITY_TYPE_COLORS[type] || 'default'}>
          {type.toUpperCase()}
        </Tag>
      ),
    },
    {
      title: '关系',
      key: 'relation',
      render: (_, record) => {
        const relation = neighbors.relations.find(
          r => r.source_id === selectedEntity?.id && r.target_id === record.id
        );
        return relation ? (
          <Tag color="blue">{relation.relation_type}</Tag>
        ) : (
          <Tag color="default">related</Tag>
        );
      },
    },
  ];

  return (
    <div style={{ padding: 24 }}>
      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card
            title={
              <Space>
                <NodeIndexOutlined />
                知识图谱
              </Space>
            }
            extra={
              <Space>
                <Button icon={<ReloadOutlined />} onClick={fetchStats}>
                  刷新
                </Button>
                <Button
                  type="primary"
                  icon={<SearchOutlined />}
                  onClick={() => setSearchModalVisible(true)}
                >
                  搜索实体
                </Button>
              </Space>
            }
          >
            <Row gutter={16}>
              <Col span={6}>
                <Statistic
                  title="实体总数"
                  value={stats?.total_entities || 0}
                  prefix={<ApartmentOutlined />}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="关系总数"
                  value={stats?.total_relations || 0}
                  prefix={<NodeIndexOutlined />}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="实体类型"
                  value={Object.keys(stats?.entity_types || {}).length}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="关系类型"
                  value={Object.keys(stats?.relation_types || {}).length}
                />
              </Col>
            </Row>
          </Card>
        </Col>

        <Col span={24}>
          <Card title="实体列表">
            <Table
              columns={entityColumns}
              dataSource={entities}
              rowKey="id"
              loading={loading}
              pagination={{ pageSize: 10 }}
            />
          </Card>
        </Col>

        {selectedEntity && (
          <Col span={24}>
            <Card
              title={`实体详情: ${selectedEntity.name}`}
              extra={
                <Tag color={ENTITY_TYPE_COLORS[selectedEntity.entity_type] || 'default'}>
                  {selectedEntity.entity_type.toUpperCase()}
                </Tag>
              }
            >
              <Row gutter={16}>
                <Col span={12}>
                  <Descriptions column={1} bordered size="small">
                    <Descriptions.Item label="ID">{selectedEntity.id}</Descriptions.Item>
                    <Descriptions.Item label="名称">{selectedEntity.name}</Descriptions.Item>
                    <Descriptions.Item label="类型">{selectedEntity.entity_type}</Descriptions.Item>
                    <Descriptions.Item label="置信度">
                      {(selectedEntity.confidence * 100).toFixed(0)}%
                    </Descriptions.Item>
                    <Descriptions.Item label="来源">{selectedEntity.source}</Descriptions.Item>
                    {selectedEntity.aliases.length > 0 && (
                      <Descriptions.Item label="别名">
                        <Space size={[0, 4]} wrap>
                          {selectedEntity.aliases.map(alias => (
                            <Tag key={alias}>{alias}</Tag>
                          ))}
                        </Space>
                      </Descriptions.Item>
                    )}
                  </Descriptions>
                </Col>
                <Col span={12}>
                  <Card title="属性" size="small">
                    <List
                      size="small"
                      dataSource={Object.entries(selectedEntity.properties)}
                      renderItem={([key, value]) => (
                        <List.Item>
                          <Text strong>{key}:</Text> <Text>{String(value)}</Text>
                        </List.Item>
                      )}
                    />
                  </Card>
                </Col>
              </Row>

              {neighbors.entities.length > 0 && (
                <Card title="关联实体" style={{ marginTop: 16 }}>
                  <Table
                    columns={neighborColumns}
                    dataSource={neighbors.entities}
                    rowKey="id"
                    pagination={false}
                    size="small"
                  />
                </Card>
              )}
            </Card>
          </Col>
        )}

        <Col span={12}>
          <Card title="实体类型分布">
            <Descriptions column={1}>
              {Object.entries(stats?.entity_types || {}).map(([type, count]) => (
                <Descriptions.Item key={type} label={
                  <Tag color={ENTITY_TYPE_COLORS[type] || 'default'}>{type}</Tag>
                }>
                  {count} 个
                </Descriptions.Item>
              ))}
            </Descriptions>
          </Card>
        </Col>

        <Col span={12}>
          <Card title="关系类型分布">
            <Descriptions column={1}>
              {Object.entries(stats?.relation_types || {}).map(([type, count]) => (
                <Descriptions.Item key={type} label={
                  <Tag color="blue">{type}</Tag>
                }>
                  {count} 条
                </Descriptions.Item>
              ))}
            </Descriptions>
          </Card>
        </Col>
      </Row>

      <Modal
        title="搜索实体"
        open={searchModalVisible}
        onCancel={() => setSearchModalVisible(false)}
        footer={null}
      >
        <Form form={form} onFinish={handleSearch} layout="vertical">
          <Form.Item name="query" label="搜索关键词" rules={[{ required: true }]}>
            <Input placeholder="输入CVE、IP、域名、恶意软件名称..." />
          </Form.Item>
          <Form.Item name="entity_type" label="实体类型">
            <Select placeholder="选择类型（可选）" allowClear>
              <Select.Option value="cve">CVE</Select.Option>
              <Select.Option value="malware">恶意软件</Select.Option>
              <Select.Option value="ip">IP地址</Select.Option>
              <Select.Option value="domain">域名</Select.Option>
              <Select.Option value="hash">哈希</Select.Option>
              <Select.Option value="technique">ATT&CK技术</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" block>
              搜索
            </Button>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
