import { useState } from 'react';
import { Card, Input, Button, Table, Tag, Space, message, Upload, Typography } from 'antd';
import { SearchOutlined, UploadOutlined, DownloadOutlined } from '@ant-design/icons';
import { bulkIoCLookup, type IoCResultItem } from '../../api/ioc';

const { TextArea } = Input;
const { Text } = Typography;

const RISK_COLORS: Record<string, string> = {
  critical: 'red',
  high: 'orange',
  medium: 'gold',
  low: 'green',
  safe: 'blue',
};

export default function IoCBulk() {
  const [input, setInput] = useState('');
  const [results, setResults] = useState<IoCResultItem[]>([]);
  const [loading, setLoading] = useState(false);

  const handleLookup = async () => {
    const indicators = input
      .split(/[\n,;]+/)
      .map((s) => s.trim())
      .filter(Boolean);

    if (indicators.length === 0) {
      message.warning('请输入至少一个 IoC 指标');
      return;
    }
    if (indicators.length > 50) {
      message.warning('单次最多 50 个指标');
      return;
    }

    setLoading(true);
    try {
      const resp = await bulkIoCLookup(indicators);
      setResults(resp.results);
      message.success(`查询完成: ${resp.success_count}/${resp.total} 成功`);
    } catch (err: any) {
      message.error(err?.response?.data?.detail || '查询失败');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      setInput(text);
    };
    reader.readAsText(file);
    return false; // prevent auto upload
  };

  const handleExport = () => {
    if (!results.length) return;
    const csv = ['indicator,type,risk_level,success'].concat(
      results.map((r) => `${r.indicator},${r.ioc_type},${r.risk_level || ''},${r.success}`)
    ).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'ioc-results.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  const columns = [
    { title: '指标', dataIndex: 'indicator', key: 'indicator', ellipsis: true },
    {
      title: '类型',
      dataIndex: 'ioc_type',
      key: 'type',
      width: 90,
      render: (v: string) => <Tag>{v}</Tag>,
    },
    {
      title: '风险等级',
      dataIndex: 'risk_level',
      key: 'risk',
      width: 100,
      render: (v: string) =>
        v ? <Tag color={RISK_COLORS[v] || 'default'}>{v.toUpperCase()}</Tag> : '-',
    },
    {
      title: '状态',
      key: 'status',
      width: 80,
      render: (_: any, record: IoCResultItem) =>
        record.success ? (
          <Tag color="green">成功</Tag>
        ) : (
          <Tag color="red">失败</Tag>
        ),
    },
    {
      title: '详情',
      dataIndex: 'error',
      key: 'detail',
      ellipsis: true,
      render: (err: string, record: IoCResultItem) => {
        if (err) return <Text type="danger">{err}</Text>;
        const d = record.data;
        if (!d) return '-';
        const parts: string[] = [];
        // sources is an array of {source, score, tags, raw, found}
        const sources: any[] = d.sources || [];
        for (const s of sources) {
          if (s.source === 'otx') {
            const pulseCount = s.raw?.pulse_info?.count ?? 0;
            if (pulseCount > 0) parts.push(`OTX: ${pulseCount} pulses`);
            else if (s.found) parts.push('OTX: matched');
          }
          if (s.source === 'virustotal') {
            const stats = s.raw?.data?.attributes?.last_analysis_stats;
            const malicious = stats?.malicious ?? 0;
            const suspicious = stats?.suspicious ?? 0;
            if (malicious > 0) parts.push(`VT: ${malicious} malicious`);
            else if (suspicious > 0) parts.push(`VT: ${suspicious} suspicious`);
            else if (s.found) parts.push('VT: flagged');
          }
        }
        if (d.found === false && parts.length === 0) return '未命中情报源';
        if (d.tags?.length) parts.push(`标签: ${d.tags.slice(0, 3).join(', ')}`);
        return parts.join(' | ') || '-';
      },
    },
  ];

  return (
    <div className="page-shell" style={{ flexDirection: 'column', gap: 16 }}>
      <Card title="IoC 批量查询">
        <Space direction="vertical" style={{ width: '100%' }} size="middle">
          <Text type="secondary">
            输入 IP、域名、Hash 或 URL（每行一个，或用逗号/分号分隔），最多 50 个。自动识别类型并查询 VirusTotal + OTX。
          </Text>
          <TextArea
            rows={6}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={`1.2.3.4\nexample.com\nd41d8cd98f00b204e9800998ecf8427e\nhttps://malicious.example/payload`}
          />
          <Space>
            <Button type="primary" icon={<SearchOutlined />} onClick={handleLookup} loading={loading}>
              批量查询
            </Button>
            <Upload beforeUpload={handleFileUpload} showUploadList={false} accept=".txt,.csv">
              <Button icon={<UploadOutlined />}>导入文件</Button>
            </Upload>
            {results.length > 0 && (
              <Button icon={<DownloadOutlined />} onClick={handleExport}>
                导出 CSV
              </Button>
            )}
          </Space>
        </Space>
      </Card>

      {results.length > 0 && (
        <Card title={`查询结果 (${results.length} 条)`}>
          <Table
            dataSource={results}
            columns={columns}
            rowKey="indicator"
            size="small"
            pagination={{ pageSize: 20 }}
            scroll={{ x: 700 }}
          />
        </Card>
      )}
    </div>
  );
}
