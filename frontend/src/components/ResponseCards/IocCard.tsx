import { Card, Tag, Table, Typography, Progress, Descriptions } from 'antd';
import { SafetyOutlined } from '@ant-design/icons';
import { getScoreColor, getScoreStatus, parseNumericScore } from '../../utils/helpers';

const { Text, Paragraph } = Typography;

interface IntelSource {
  source: string;
  score: string;
  tags: string;
  status: string;
}

interface IocData {
  indicator: string;
  indicatorType: string;
  threatScore: string;
  sources: IntelSource[];
  firstSeen: string;
  lastSeen: string;
  malwareFamily: string;
  campaign: string;
  fixSuggestions: string[];
  dataSources: string[];
}

function parseIocMarkdown(content: string): IocData | null {
  const data: IocData = {
    indicator: '',
    indicatorType: '',
    threatScore: '',
    sources: [],
    firstSeen: '',
    lastSeen: '',
    malwareFamily: '',
    campaign: '',
    fixSuggestions: [],
    dataSources: [],
  };

  // Parse header: ## IoC 分析报告 - xxx
  const headerMatch = content.match(/^##\s*IoC\s*分析报告\s*-\s*(.+)/m);
  if (headerMatch) data.indicator = headerMatch[1].trim();

  // Parse type and score
  const typeMatch = content.match(/\*\*指标类型[：:]\s*(.+?)\*\*/);
  if (typeMatch) data.indicatorType = typeMatch[1].trim();

  const scoreMatch = content.match(/\*\*综合威胁评分[：:]\s*(\d+)/);
  if (scoreMatch) data.threatScore = scoreMatch[1];

  // Parse multi-source table
  const srcSection = content.split(/###\s*多源情报汇总/)[1]?.split(/###\s*/)[0] || '';
  const tableRows = srcSection.match(/\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|/g);
  if (tableRows) {
    for (const row of tableRows) {
      const cells = row.split('|').map(c => c.trim()).filter(Boolean);
      if (cells.length >= 4 && !cells[0].match(/^[-]+$/) && !cells[0].match(/^来源$/)) {
        data.sources.push({
          source: cells[0],
          score: cells[1],
          tags: cells[2],
          status: cells[3],
        });
      }
    }
  }

  // Parse related info
  const relatedSection = content.split(/###\s*关联信息/)[1]?.split(/###\s*/)[0] || '';
  const firstSeenMatch = relatedSection.match(/\*\*首次发现[：:]\*\*\s*(.+)/);
  if (firstSeenMatch) data.firstSeen = firstSeenMatch[1].trim();

  const lastSeenMatch = relatedSection.match(/\*\*最近活动[：:]\*\*\s*(.+)/);
  if (lastSeenMatch) data.lastSeen = lastSeenMatch[1].trim();

  const familyMatch = relatedSection.match(/\*\*关联家族[：:]\*\*\s*(.+)/);
  if (familyMatch) data.malwareFamily = familyMatch[1].trim();

  const campaignMatch = relatedSection.match(/\*\*关联 Campaign[：:]\*\*\s*(.+)/);
  if (campaignMatch) data.campaign = campaignMatch[1].trim();

  // Parse fix suggestions
  const fixSection = content.split(/###\s*处置建议/)[1]?.split(/###\s*/)[0] || '';
  const fixLines = fixSection.match(/^\d+\.\s*(.+)/gm);
  if (fixLines) {
    data.fixSuggestions = fixLines.map(l => l.replace(/^\d+\.\s*/, ''));
  }

  // Parse sources
  const dsSection = content.split(/###\s*数据来源/)[1]?.split(/###\s*/)[0] || '';
  const dsLines = dsSection.match(/^-\s*(.+)/gm);
  if (dsLines) {
    data.dataSources = dsLines.map(l => l.replace(/^-\s*/, ''));
  }

  return data.indicator ? data : null;
}

export default function IocCard({ content }: { content: string }) {
  const data = parseIocMarkdown(content);
  if (!data) return <div className="markdown-body">{content}</div>;

  const threatScore = parseInt(data.threatScore, 10) || 0;
  const scoreColor = getScoreColor(threatScore);

  const sourceColumns = [
    { title: '来源', dataIndex: 'source', key: 'source', width: 100 },
    {
      title: '评分',
      dataIndex: 'score',
      key: 'score',
      width: 160,
      render: (score: string) => {
        const num = parseNumericScore(score);
        return (
          <Progress
            percent={num}
            size="small"
            status={getScoreStatus(num)}
            style={{ marginBottom: 0 }}
          />
        );
      },
    },
    { title: '标签', dataIndex: 'tags', key: 'tags' },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 80,
      render: (status: string) => {
        const s = status.toLowerCase();
        const color = s.includes('malicious') || s.includes('恶意') ? 'red'
          : s.includes('suspicious') || s.includes('可疑') ? 'orange'
          : s.includes('clean') || s.includes('安全') ? 'green'
          : 'default';
        return <Tag color={color}>{status}</Tag>;
      },
    },
  ];

  return (
    <Card
      size="small"
      title={
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <SafetyOutlined style={{ color: scoreColor }} />
          <span>IoC 分析</span>
          <Tag>{data.indicatorType}</Tag>
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
      <Text strong style={{ display: 'block', marginBottom: 8, fontFamily: 'monospace' }}>
        {data.indicator}
      </Text>

      {data.sources.length > 0 && (
        <Table
          dataSource={data.sources}
          columns={sourceColumns}
          pagination={false}
          size="small"
          rowKey="source"
          style={{ marginBottom: 12 }}
        />
      )}

      {(data.firstSeen || data.lastSeen || data.malwareFamily || data.campaign) && (
        <Descriptions size="small" column={2} style={{ marginBottom: 12 }}>
          {data.firstSeen && <Descriptions.Item label="首次发现">{data.firstSeen}</Descriptions.Item>}
          {data.lastSeen && <Descriptions.Item label="最近活动">{data.lastSeen}</Descriptions.Item>}
          {data.malwareFamily && <Descriptions.Item label="关联家族">{data.malwareFamily}</Descriptions.Item>}
          {data.campaign && <Descriptions.Item label="关联 Campaign">{data.campaign}</Descriptions.Item>}
        </Descriptions>
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
