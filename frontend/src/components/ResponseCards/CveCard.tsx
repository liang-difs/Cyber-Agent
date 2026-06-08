import { Card, Tag, Table, Typography, Descriptions } from 'antd';
import { BugOutlined } from '@ant-design/icons';

const { Text, Paragraph } = Typography;

interface CveData {
  cveId: string;
  summary: string;
  severity: string;
  cvssScore: string;
  vulnType: string;
  infoRows: { key: string; value: string }[];
  affectedVersions: string[];
  description: string;
  fixSuggestions: string[];
  sources: string[];
}

function getCvssColor(score: string): string {
  const n = parseFloat(score);
  if (isNaN(n)) return '#d9d9d9';
  if (n >= 9) return '#f5222d';
  if (n >= 7) return '#fa8c16';
  if (n >= 4) return '#fadb14';
  return '#52c41a';
}

function getSeverityLabel(severity: string): { text: string; color: string } {
  const s = severity.toLowerCase();
  if (s.includes('critical')) return { text: '严重', color: '#f5222d' };
  if (s.includes('high')) return { text: '高危', color: '#fa8c16' };
  if (s.includes('medium')) return { text: '中危', color: '#fadb14' };
  if (s.includes('low')) return { text: '低危', color: '#52c41a' };
  return { text: severity || '未知', color: '#d9d9d9' };
}

function parseCveMarkdown(content: string): CveData | null {
  const lines = content.split('\n');
  const data: CveData = {
    cveId: '',
    summary: '',
    severity: '',
    cvssScore: '',
    vulnType: '',
    infoRows: [],
    affectedVersions: [],
    description: '',
    fixSuggestions: [],
    sources: [],
  };

  // Parse header: ## CVE-xxxx-xxxx - 描述
  const headerMatch = content.match(/^##\s+(CVE-\d+-\d+)\s*-\s*(.+)/m);
  if (headerMatch) {
    data.cveId = headerMatch[1];
    data.summary = headerMatch[2];
  }

  // Parse severity line: **风险等级：Critical** | **CVSS 评分：9.8** | **漏洞类型：xxx**
  const severityLine = content.match(/\*\*风险等级[：:]\s*(.+?)\*\*/);
  if (severityLine) data.severity = severityLine[1].trim();

  const cvssMatch = content.match(/\*\*CVSS 评分[：:]\s*([\d.]+)/);
  if (cvssMatch) data.cvssScore = cvssMatch[1];

  const typeMatch = content.match(/\*\*漏洞类型[：:]\s*(.+?)\*\*/);
  if (typeMatch) data.vulnType = typeMatch[1].trim();

  // Parse table rows in 基本信息 section
  const infoSection = content.split(/###\s*基本信息/)[1]?.split(/###\s*/)[0] || '';
  const tableRows = infoSection.match(/\|\s*(.+?)\s*\|\s*(.+?)\s*\|/g);
  if (tableRows) {
    for (const row of tableRows) {
      const cells = row.split('|').map(c => c.trim()).filter(Boolean);
      if (cells.length >= 2 && !cells[0].match(/^[-]+$/)) {
        data.infoRows.push({ key: cells[0], value: cells[1] });
      }
    }
  }

  // Parse affected versions
  const versionsSection = content.split(/###\s*影响版本/)[1]?.split(/###\s*/)[0] || '';
  const versionLines = versionsSection.match(/^-\s*(.+)/gm);
  if (versionLines) {
    data.affectedVersions = versionLines.map(l => l.replace(/^-\s*/, ''));
  }

  // Parse description
  const descSection = content.split(/###\s*漏洞描述/)[1]?.split(/###\s*/)[0] || '';
  data.description = descSection.trim();

  // Parse fix suggestions
  const fixSection = content.split(/###\s*修复建议/)[1]?.split(/###\s*/)[0] || '';
  const fixLines = fixSection.match(/^\d+\.\s*(.+)/gm);
  if (fixLines) {
    data.fixSuggestions = fixLines.map(l => l.replace(/^\d+\.\s*/, ''));
  }

  // Parse sources
  const srcSection = content.split(/###\s*数据来源/)[1]?.split(/###\s*/)[0] || '';
  const srcLines = srcSection.match(/^-\s*(.+)/gm);
  if (srcLines) {
    data.sources = srcLines.map(l => l.replace(/^-\s*/, ''));
  }

  return data.cveId ? data : null;
}

export default function CveCard({ content }: { content: string }) {
  const data = parseCveMarkdown(content);
  if (!data) return <div className="markdown-body">{content}</div>;

  const sev = getSeverityLabel(data.severity);
  const cvssColor = getCvssColor(data.cvssScore);

  const infoColumns = [
    { title: '项目', dataIndex: 'key', key: 'key', width: 120 },
    { title: '详情', dataIndex: 'value', key: 'value' },
  ];

  return (
    <Card
      size="small"
      title={
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <BugOutlined style={{ color: cvssColor }} />
          <span>{data.cveId}</span>
          <Tag color={sev.color}>{sev.text}</Tag>
          {data.cvssScore && (
            <Tag
              color={cvssColor}
              style={{ color: parseFloat(data.cvssScore) >= 7 ? '#fff' : '#000', fontWeight: 600 }}
            >
              CVSS {data.cvssScore}
            </Tag>
          )}
        </div>
      }
      styles={{ body: { padding: '12px 16px' } }}
      style={{ marginBottom: 8 }}
    >
      <Text type="secondary" style={{ display: 'block', marginBottom: 12 }}>
        {data.summary}
      </Text>

      {data.infoRows.length > 0 && (
        <Table
          dataSource={data.infoRows}
          columns={infoColumns}
          pagination={false}
          size="small"
          rowKey="key"
          style={{ marginBottom: 12 }}
        />
      )}

      {data.affectedVersions.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <Text strong>影响版本：</Text>
          <div style={{ marginTop: 4 }}>
            {data.affectedVersions.map((v, i) => (
              <Tag key={i} style={{ marginBottom: 4 }}>{v}</Tag>
            ))}
          </div>
        </div>
      )}

      {data.description && (
        <div style={{ marginBottom: 12 }}>
          <Text strong>漏洞描述：</Text>
          <Paragraph style={{ marginTop: 4 }}>{data.description}</Paragraph>
        </div>
      )}

      {data.fixSuggestions.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <Text strong>修复建议：</Text>
          <ol style={{ margin: '4px 0 0 20px', padding: 0 }}>
            {data.fixSuggestions.map((s, i) => (
              <li key={i} style={{ marginBottom: 2 }}>{s}</li>
            ))}
          </ol>
        </div>
      )}

      {data.sources.length > 0 && (
        <Descriptions size="small" column={1} style={{ marginTop: 8 }}>
          <Descriptions.Item label="数据来源">
            {data.sources.map((s, i) => (
              <Tag key={i} style={{ marginBottom: 2 }}>{s}</Tag>
            ))}
          </Descriptions.Item>
        </Descriptions>
      )}
    </Card>
  );
}
