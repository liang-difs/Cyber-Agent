import { Card, Tag, Table, Typography, Descriptions, Progress } from 'antd';
import { GlobalOutlined, EnvironmentOutlined } from '@ant-design/icons';

const { Text } = Typography;

interface ScoreDimension {
  dimension: string;
  score: string;
  weight: string;
  detail: string;
}

interface IpData {
  ip: string;
  country: string;
  city: string;
  isp: string;
  threatScore: string;
  dimensions: ScoreDimension[];
  fixSuggestions: string[];
  dataSources: string[];
}

function getScoreColor(score: number): string {
  if (score >= 80) return '#f5222d';
  if (score >= 60) return '#fa8c16';
  if (score >= 40) return '#fadb14';
  return '#52c41a';
}

function parseIpMarkdown(content: string): IpData | null {
  const data: IpData = {
    ip: '',
    country: '',
    city: '',
    isp: '',
    threatScore: '',
    dimensions: [],
    fixSuggestions: [],
    dataSources: [],
  };

  // Parse header: ## IP 威胁分析报告 - x.x.x.x
  const headerMatch = content.match(/^##\s*IP\s*威胁分析报告\s*-\s*(.+)/m);
  if (headerMatch) data.ip = headerMatch[1].trim();

  // Parse location/ISP line
  const geoMatch = content.match(/\*\*归属地[：:]\s*(.+?),\s*(.+?)\*\*/);
  if (geoMatch) {
    data.country = geoMatch[1].trim();
    data.city = geoMatch[2].trim();
  }

  const ispMatch = content.match(/\*\*ISP[：:]\s*(.+?)\*\*/);
  if (ispMatch) data.isp = ispMatch[1].trim();

  const scoreMatch = content.match(/\*\*威胁评分[：:]\s*(\d+)/);
  if (scoreMatch) data.threatScore = scoreMatch[1];

  // Parse score dimensions table
  const dimSection = content.split(/###\s*评分构成/)[1]?.split(/###\s*/)[0] || '';
  const tableRows = dimSection.match(/\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|/g);
  if (tableRows) {
    for (const row of tableRows) {
      const cells = row.split('|').map(c => c.trim()).filter(Boolean);
      if (cells.length >= 4 && !cells[0].match(/^[-]+$/) && !cells[0].match(/^维度$/)) {
        data.dimensions.push({
          dimension: cells[0],
          score: cells[1],
          weight: cells[2],
          detail: cells[3],
        });
      }
    }
  }

  // Parse fix suggestions
  const fixSection = content.split(/###\s*处置建议/)[1]?.split(/###\s*/)[0] || '';
  const fixLines = fixSection.match(/^\d+\.\s*(.+)/gm);
  if (fixLines) {
    data.fixSuggestions = fixLines.map(l => l.replace(/^\d+\.\s*/, ''));
  }

  // Parse sources
  const srcSection = content.split(/###\s*数据来源/)[1]?.split(/###\s*/)[0] || '';
  const srcLines = srcSection.match(/^-\s*(.+)/gm);
  if (srcLines) {
    data.dataSources = srcLines.map(l => l.replace(/^-\s*/, ''));
  }

  return data.ip ? data : null;
}

function parseNumericScore(scoreStr: string): number {
  const match = scoreStr.match(/(\d+)/);
  return match ? parseInt(match[1], 10) : 0;
}

export default function IpCard({ content }: { content: string }) {
  const data = parseIpMarkdown(content);
  if (!data) return <div className="markdown-body">{content}</div>;

  const threatScore = parseInt(data.threatScore, 10) || 0;
  const scoreColor = getScoreColor(threatScore);

  const dimColumns = [
    { title: '维度', dataIndex: 'dimension', key: 'dimension', width: 100 },
    {
      title: '分值',
      dataIndex: 'score',
      key: 'score',
      width: 120,
      render: (score: string) => {
        const num = parseNumericScore(score);
        return (
          <Progress
            percent={num}
            size="small"
            strokeColor={getScoreColor(num)}
            style={{ marginBottom: 0 }}
          />
        );
      },
    },
    { title: '权重', dataIndex: 'weight', key: 'weight', width: 80 },
    { title: '说明', dataIndex: 'detail', key: 'detail' },
  ];

  return (
    <Card
      size="small"
      title={
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <GlobalOutlined style={{ color: scoreColor }} />
          <span>IP 威胁分析</span>
          {data.country && (
            <Tag icon={<EnvironmentOutlined />}>
              {data.country}{data.city ? `, ${data.city}` : ''}
            </Tag>
          )}
          <Tag
            color={scoreColor}
            style={{ color: threatScore >= 60 ? '#fff' : '#000', fontWeight: 600 }}
          >
            威胁评分 {data.threatScore}/100
          </Tag>
        </div>
      }
      styles={{ body: { padding: '12px 16px' } }}
      style={{ marginBottom: 8 }}
    >
      <Descriptions size="small" column={3} style={{ marginBottom: 12 }}>
        <Descriptions.Item label="IP 地址">
          <Text strong style={{ fontFamily: 'monospace' }}>{data.ip}</Text>
        </Descriptions.Item>
        {data.isp && <Descriptions.Item label="ISP">{data.isp}</Descriptions.Item>}
      </Descriptions>

      {data.dimensions.length > 0 && (
        <Table
          dataSource={data.dimensions}
          columns={dimColumns}
          pagination={false}
          size="small"
          rowKey="dimension"
          style={{ marginBottom: 12 }}
        />
      )}

      {data.fixSuggestions.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <Text strong>处置建议：</Text>
          <ol style={{ margin: '4px 0 0 20px', padding: 0 }}>
            {data.fixSuggestions.map((s, i) => (
              <li key={i} style={{ marginBottom: 2 }}>{s}</li>
            ))}
          </ol>
        </div>
      )}

      {data.dataSources.length > 0 && (
        <Descriptions size="small" column={1}>
          <Descriptions.Item label="数据来源">
            {data.dataSources.map((s, i) => (
              <Tag key={i} style={{ marginBottom: 2 }}>{s}</Tag>
            ))}
          </Descriptions.Item>
        </Descriptions>
      )}
    </Card>
  );
}
