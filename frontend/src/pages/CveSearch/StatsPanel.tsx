import { Card, Statistic, Row, Col } from 'antd';
import ReactECharts from 'echarts-for-react';
import type { CveStatsResponse } from '../../types/api';
import { SEVERITY_HEX_COLORS as severityColors } from '../../constants/severity';

interface Props {
  stats: CveStatsResponse | null;
  loading: boolean;
}

export default function StatsPanel({ stats, loading }: Props) {
  if (!stats) return null;

  const pieData = Object.entries(stats.by_severity).map(([name, value]) => ({
    name,
    value,
    itemStyle: { color: severityColors[name] || '#d9d9d9' },
  }));

  const option = {
    tooltip: { trigger: 'item' as const },
    legend: { bottom: 0 },
    series: [
      {
        type: 'pie',
        radius: ['40%', '70%'],
        avoidLabelOverlap: false,
        label: { show: false },
        data: pieData,
      },
    ],
  };

  return (
    <Card title="CVE 统计" loading={loading} className="page-card-fill" style={{ marginBottom: 16 }}>
      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={8}>
          <Statistic title="总计" value={stats.total} />
        </Col>
        <Col xs={8}>
          <Statistic
            title="严重"
            value={stats.by_severity.CRITICAL || 0}
            valueStyle={{ color: '#ff4d4f' }}
          />
        </Col>
        <Col xs={8}>
          <Statistic
            title="高危"
            value={stats.by_severity.HIGH || 0}
            valueStyle={{ color: '#fa8c16' }}
          />
        </Col>
      </Row>
      <ReactECharts option={option} style={{ height: 200 }} />
    </Card>
  );
}
