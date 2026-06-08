import { useState, useCallback } from 'react';
import { Card, Tabs, Table, Tag, Button, Row, Col, Statistic, Timeline, Empty, message, InputNumber, Space } from 'antd';
import { ApartmentOutlined, ReloadOutlined } from '@ant-design/icons';
import ReactECharts from 'echarts-for-react';
import { getAttackChains, correlateAlerts } from '../../api/analysis';
import type { AttackChainResponse, CorrelationResponse, AttackChain, CorrelationPattern } from '../../types/api';

const TACTIC_COLORS: Record<string, string> = {
  Reconnaissance: '#1890ff',
  InitialAccess: '#fa8c16',
  Execution: '#eb2f96',
  Persistence: '#722ed1',
  CredentialAccess: '#fa541c',
  LateralMovement: '#13c2c2',
  CommandAndControl: '#f5222d',
  Exfiltration: '#a0d911',
  Impact: '#ff4d4f',
  Discovery: '#597ef7',
};

import { SEVERITY_TAG_COLORS as SEVERITY_COLORS } from '../../constants/severity';

export default function AttackChainPage() {
  const [chainData, setChainData] = useState<AttackChainResponse | null>(null);
  const [corrData, setCorrData] = useState<CorrelationResponse | null>(null);
  const [chainLoading, setChainLoading] = useState(false);
  const [corrLoading, setCorrLoading] = useState(false);

  const fetchChains = useCallback(async () => {
    setChainLoading(true);
    try {
      const data = await getAttackChains({ time_window_hours: 24 });
      setChainData(data);
      if (data.warning) message.warning(data.warning);
    } catch {
      message.error('获取攻击链失败');
    } finally {
      setChainLoading(false);
    }
  }, []);

  const fetchCorrelation = useCallback(async () => {
    setCorrLoading(true);
    try {
      const data = await correlateAlerts();
      setCorrData(data);
      if (data.warning) message.warning(data.warning);
    } catch {
      message.error('获取关联分析失败');
    } finally {
      setCorrLoading(false);
    }
  }, []);

  const patternColumns = [
    {
      title: '模式类型',
      dataIndex: 'pattern_type',
      key: 'pattern_type',
      render: (v: string) => <Tag color="purple">{v}</Tag>,
    },
    {
      title: '描述',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
    },
    {
      title: '置信度',
      dataIndex: 'confidence',
      key: 'confidence',
      render: (v: number) => (
        <span style={{ color: v >= 0.8 ? '#cf1322' : v >= 0.5 ? '#fa8c16' : '#3f8600' }}>
          {(v * 100).toFixed(0)}%
        </span>
      ),
    },
    {
      title: '关联告警数',
      dataIndex: 'related_alerts',
      key: 'related_alerts',
      render: (v: string[]) => v?.length ?? 0,
    },
  ];

  const ipChartOption = corrData?.top_src_ips?.length
    ? {
        tooltip: { trigger: 'axis' as const },
        xAxis: {
          type: 'category' as const,
          data: corrData.top_src_ips.slice(0, 10).map((e) => e.ip),
          axisLabel: { rotate: 30 },
        },
        yAxis: { type: 'value' as const },
        series: [
          {
            type: 'bar' as const,
            data: corrData.top_src_ips.slice(0, 10).map((e) => e.count),
            itemStyle: { color: '#1890ff' },
          },
        ],
      }
    : null;

  return (
    <div className="page-shell" style={{ flexDirection: 'column' }}>
      <Tabs
        className="page-tabs-fill"
        style={{ flex: 1 }}
        items={[
          {
            key: 'chains',
            label: (
              <span>
                <ApartmentOutlined />
                攻击链溯源
              </span>
            ),
            children: (
              <Card
                extra={
                  <Button icon={<ReloadOutlined />} onClick={fetchChains} loading={chainLoading}>
                    分析攻击链
                  </Button>
                }
                className="page-card-fill"
                style={{ display: 'flex', flexDirection: 'column' }}
              >
                {!chainData && <Empty description="点击按钮开始攻击链溯源分析" />}
                {chainData && chainData.chains.length === 0 && (
                  <Empty description={chainData.warning || '未发现攻击链（告警数据不足或无关联）'} />
                )}
                {chainData?.chains?.map((chain: AttackChain) => (
                  <Card
                    key={chain.chain_id}
                    title={
                      <Space>
                        <span>{chain.chain_id}</span>
                        <Tag color={SEVERITY_COLORS[chain.severity]}>{chain.severity.toUpperCase()}</Tag>
                        <Tag>进展: {(chain.progression_score * 100).toFixed(0)}%</Tag>
                      </Space>
                    }
                    size="small"
                    style={{ marginBottom: 16 }}
                  >
                    <Row gutter={[16, 16]} style={{ marginBottom: 12 }}>
                      <Col xs={12} md={6}>
                        <Statistic title="告警数" value={chain.length} />
                      </Col>
                      <Col xs={12} md={6}>
                        <Statistic title="进展评分" value={`${(chain.progression_score * 100).toFixed(0)}%`} />
                      </Col>
                      <Col xs={12} md={6}>
                        <Statistic title="源 IP 数" value={chain.src_ips.length} />
                      </Col>
                      <Col xs={12} md={6}>
                        <Statistic title="覆盖战术" value={chain.tactics_covered.length} />
                      </Col>
                    </Row>
                    <div style={{ marginBottom: 8 }}>
                      {chain.tactics_covered.map((t) => (
                        <Tag key={t} color={TACTIC_COLORS[t] || 'default'} style={{ marginBottom: 4 }}>
                          {t}
                        </Tag>
                      ))}
                    </div>
                    <Timeline
                      items={chain.nodes.map((node) => ({
                        color: TACTIC_COLORS[node.tactic] || 'blue',
                        children: (
                          <div>
                            <Tag color={TACTIC_COLORS[node.tactic]}>{node.tactic}</Tag>
                            <code>{node.rule_id}</code>
                            <span style={{ marginLeft: 8, color: '#888' }}>
                              {node.src_ip} → {node.dst_ip || '?'}
                            </span>
                            <br />
                            <small style={{ color: '#aaa' }}>
                              {new Date(node.timestamp).toLocaleString('zh-CN')}
                            </small>
                          </div>
                        ),
                      }))}
                    />
                  </Card>
                ))}
              </Card>
            ),
          },
          {
            key: 'correlation',
            label: '关联分析',
            children: (
              <Card
                extra={
                  <Button icon={<ReloadOutlined />} onClick={fetchCorrelation} loading={corrLoading}>
                    运行关联分析
                  </Button>
                }
                className="page-card-fill"
                style={{ display: 'flex', flexDirection: 'column' }}
              >
                {!corrData && <Empty description="点击按钮开始关联分析" />}
                {corrData && (
                  <>
                    <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
                      <Col xs={12} md={6}>
                        <Statistic title="总告警数" value={corrData.total_alerts} />
                      </Col>
                      <Col xs={12} md={6}>
                        <Statistic title="关联模式数" value={corrData.patterns?.length ?? 0} />
                      </Col>
                      <Col xs={12} md={6}>
                        <Statistic title="协议分布" value={Object.keys(corrData.severity_distribution || {}).length} />
                      </Col>
                      <Col xs={12} md={6}>
                        <Statistic title="源 IP 数" value={corrData.top_src_ips?.length ?? 0} />
                      </Col>
                    </Row>

                    <Card title="关联模式" size="small" style={{ marginBottom: 16 }}>
                      <Table
                        dataSource={corrData.patterns || []}
                        columns={patternColumns}
                        rowKey={(_, i) => String(i)}
                        pagination={false}
                        size="small"
                        scroll={{ x: 760 }}
                      />
                    </Card>

                    {ipChartOption && (
                      <Card title="Top 源 IP" size="small">
                        <ReactECharts option={ipChartOption} style={{ height: 300 }} />
                      </Card>
                    )}
                  </>
                )}
              </Card>
            ),
          },
        ]}
      />
    </div>
  );
}
