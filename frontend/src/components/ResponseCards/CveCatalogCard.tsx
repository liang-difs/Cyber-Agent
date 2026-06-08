import { Card, Tag, Table, Typography, Descriptions } from 'antd';
import { BarChartOutlined } from '@ant-design/icons';

const { Text, Paragraph } = Typography;

interface CatalogSample {
  cveId: string;
  docId: string;
  published: string;
  cvssScore: string;
  severity: string;
  isKev: boolean;
  kevDate: string;
  vendor: string;
  product: string;
  sourcePath: string;
}

interface CatalogEvidence {
  cveId: string;
  sourceType: string;
  sourcePath: string;
  docId: string;
  keyDates: string;
  note: string;
}

interface CatalogData {
  summaryText: string;
  matchedCount: string;
  kevCount: string;
  kevHitRate: string;
  returnedCount: string;
  byYear: string;
  bySeverity: string;
  kevByYear: string;
  kevBySeverity: string;
  samples: CatalogSample[];
  evidence: CatalogEvidence[];
}

function parseBlockValue(content: string, heading: string): string {
  const section = content.split(new RegExp(`###\\s*${heading}`))[1]?.split(/###\s*/)[0] || '';
  return section.trim();
}

function parseCatalogMarkdown(content: string): CatalogData | null {
  const headerMatch = content.match(/^##\s*CVE\s*\/\s*KEV\s*结构化查询结果/m);
  if (!headerMatch) return null;

  const summaryMatch = content.match(/^##\s*结论\s*\n+([\s\S]*?)\n+##\s*统计摘要/m);
  const summaryText = summaryMatch ? summaryMatch[1].trim() : '';

  const statsSection = parseBlockValue(content, '统计摘要');
  const matchedCount = (statsSection.match(/-\s*命中总数[：:]\s*(.+)/)?.[1] || '').trim();
  const kevCount = (statsSection.match(/-\s*KEV 命中数[：:]\s*(.+)/)?.[1] || '').trim();
  const kevHitRate = (statsSection.match(/-\s*KEV 命中率[：:]\s*(.+)/)?.[1] || '').trim();
  const returnedCount = (statsSection.match(/-\s*返回条数[：:]\s*(.+)/)?.[1] || '').trim();

  const distributionSection = parseBlockValue(content, '分布统计');
  const byYear = (distributionSection.match(/-\s*按年份[：:]\s*(.+)/)?.[1] || '').trim();
  const bySeverity = (distributionSection.match(/-\s*按严重级别[：:]\s*(.+)/)?.[1] || '').trim();
  const kevByYear = (distributionSection.match(/-\s*KEV 按年份[：:]\s*(.+)/)?.[1] || '').trim();
  const kevBySeverity = (distributionSection.match(/-\s*KEV 按严重级别[：:]\s*(.+)/)?.[1] || '').trim();

  const sampleSection = parseBlockValue(content, '样本结果');
  const samples: CatalogSample[] = [];
  const tableLines = sampleSection
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('|') && !/^\|[-\s:|]+\|$/.test(line));
  for (const line of tableLines) {
    const cells = line.split('|').map((part) => part.trim()).filter(Boolean);
    if (cells.length < 9 || cells[0] === 'CVE') continue;
    samples.push({
      cveId: cells[0] || '',
      docId: cells[1] || '',
      published: cells[2] || '',
      cvssScore: cells[3] || '',
      severity: cells[4] || '',
      isKev: (cells[5] || '').includes('是'),
      kevDate: cells[6] || '',
      vendor: cells[7] || '',
      product: cells[8] || '',
      sourcePath: cells[9] || '',
    });
  }

  if (samples.length === 0) {
    const sampleLines = sampleSection.match(/^[-•]\s*(.+)$/gm) || [];
    for (const line of sampleLines) {
      const parts = line.replace(/^[-•]\s*/, '').split('|').map((part) => part.trim());
      samples.push({
        cveId: parts[0] || '',
        docId: parts[1] || '',
        published: parts[2] || '',
        cvssScore: (parts[3] || '').replace(/^CVSS\s*/i, ''),
        severity: parts[4] || '',
        isKev: (parts[5] || '').includes('是'),
        kevDate: parts[6] || '',
        vendor: parts[7] || '',
        product: parts[8] || '',
        sourcePath: parts[9] || '',
      });
    }
  }

  const evidenceSection = parseBlockValue(content, '证据');
  const evidence: CatalogEvidence[] = [];
  const evidenceLines = evidenceSection
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('|') && !/^\|[-\s:|]+\|$/.test(line));
  for (const line of evidenceLines) {
    const cells = line.split('|').map((part) => part.trim()).filter(Boolean);
    if (cells.length < 6 || cells[0] === 'CVE') continue;
    evidence.push({
      cveId: cells[0] || '',
      sourceType: cells[1] || '',
      sourcePath: cells[2] || '',
      docId: cells[3] || '',
      keyDates: cells[4] || '',
      note: cells[5] || '',
    });
  }

  return {
    summaryText,
    matchedCount,
    kevCount,
    kevHitRate,
    returnedCount,
    byYear,
    bySeverity,
    kevByYear,
    kevBySeverity,
    samples,
    evidence,
  };
}

export default function CveCatalogCard({ content }: { content: string }) {
  const data = parseCatalogMarkdown(content);
  if (!data) return <div className="markdown-body">{content}</div>;

  const sampleColumns = [
    { title: 'CVE', dataIndex: 'cveId', key: 'cveId', width: 160 },
    { title: 'doc_id', dataIndex: 'docId', key: 'docId', width: 160 },
    { title: '披露时间', dataIndex: 'published', key: 'published', width: 160 },
    { title: 'CVSS', dataIndex: 'cvssScore', key: 'cvssScore', width: 100 },
    { title: '严重级别', dataIndex: 'severity', key: 'severity', width: 120 },
    {
      title: 'KEV',
      dataIndex: 'isKev',
      key: 'isKev',
      width: 80,
      render: (value: boolean) => <Tag color={value ? 'red' : 'default'}>{value ? '是' : '否'}</Tag>,
    },
    { title: 'KEV 日期', dataIndex: 'kevDate', key: 'kevDate', width: 120 },
    { title: '厂商', dataIndex: 'vendor', key: 'vendor', width: 140 },
    { title: '产品', dataIndex: 'product', key: 'product', width: 140 },
  ];

  return (
    <Card
      size="small"
      title={
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <BarChartOutlined style={{ color: 'var(--app-primary)' }} />
          <span>CVE / KEV 结构化查询</span>
          {data.matchedCount && <Tag color="blue">命中 {data.matchedCount}</Tag>}
          {data.kevCount && <Tag color="red">KEV {data.kevCount}</Tag>}
          {data.kevHitRate && <Tag color="gold">命中率 {data.kevHitRate}</Tag>}
        </div>
      }
      styles={{ body: { padding: '12px 16px' } }}
      style={{ marginBottom: 8 }}
    >
      {data.summaryText && (
        <div style={{ marginBottom: 12 }}>
          <Text strong>结论：</Text>
          <Paragraph style={{ marginTop: 4, marginBottom: 0 }}>{data.summaryText}</Paragraph>
        </div>
      )}

      <Descriptions size="small" column={2} style={{ marginBottom: 12 }}>
        {data.matchedCount && <Descriptions.Item label="命中总数">{data.matchedCount}</Descriptions.Item>}
        {data.kevCount && <Descriptions.Item label="KEV 命中数">{data.kevCount}</Descriptions.Item>}
        {data.kevHitRate && <Descriptions.Item label="KEV 命中率">{data.kevHitRate}</Descriptions.Item>}
        {data.returnedCount && <Descriptions.Item label="返回条数">{data.returnedCount}</Descriptions.Item>}
      </Descriptions>

      {(data.byYear || data.bySeverity || data.kevByYear || data.kevBySeverity) && (
        <Descriptions size="small" column={1} style={{ marginBottom: 12 }}>
          {data.byYear && <Descriptions.Item label="按年份">{data.byYear}</Descriptions.Item>}
          {data.bySeverity && <Descriptions.Item label="按严重级别">{data.bySeverity}</Descriptions.Item>}
          {data.kevByYear && <Descriptions.Item label="KEV 按年份">{data.kevByYear}</Descriptions.Item>}
          {data.kevBySeverity && <Descriptions.Item label="KEV 按严重级别">{data.kevBySeverity}</Descriptions.Item>}
        </Descriptions>
      )}

      {data.samples.length > 0 && (
        <Table
          dataSource={data.samples}
          columns={sampleColumns}
          pagination={false}
          size="small"
          rowKey={(row, index) => `${row.cveId || 'sample'}-${index}`}
          style={{ marginBottom: 12 }}
        />
      )}

      {data.evidence.length > 0 && (
        <Table
          dataSource={data.evidence}
          columns={[
            { title: 'CVE', dataIndex: 'cveId', key: 'cveId', width: 160 },
            { title: '来源类型', dataIndex: 'sourceType', key: 'sourceType', width: 110 },
            { title: '来源路径', dataIndex: 'sourcePath', key: 'sourcePath', width: 220 },
            { title: 'doc_id', dataIndex: 'docId', key: 'docId', width: 160 },
            { title: '关键日期', dataIndex: 'keyDates', key: 'keyDates', width: 180 },
            { title: '说明', dataIndex: 'note', key: 'note' },
          ]}
          pagination={false}
          size="small"
          rowKey={(row, index) => `${row.cveId || 'evidence'}-${row.sourceType || 'src'}-${index}`}
          style={{ marginBottom: 12 }}
        />
      )}

      <Text type="secondary" style={{ display: 'block' }}>
        如果返回条数小于命中总数，这里只展示样本，不代表全集。
      </Text>
    </Card>
  );
}