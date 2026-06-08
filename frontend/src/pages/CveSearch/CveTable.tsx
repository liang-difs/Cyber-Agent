import { Table, Tag, Progress } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import type { CveItem } from '../../types/api';
import { SEVERITY_TAG_COLORS as severityColors } from '../../constants/severity';

interface Props {
  data: CveItem[];
  loading: boolean;
  total: number;
  page: number;
  pageSize: number;
  onPageChange: (page: number, pageSize: number) => void;
  onRowClick: (record: CveItem) => void;
}

const columns: ColumnsType<CveItem> = [
  {
    title: 'CVE ID',
    dataIndex: 'cve_id',
    key: 'cve_id',
    width: 150,
    render: (text: string) => <a style={{ fontWeight: 600 }}>{text}</a>,
  },
  {
    title: '严重程度',
    dataIndex: 'severity',
    key: 'severity',
    width: 110,
    render: (sev: string) => <Tag color={severityColors[sev] || 'default'}>{sev}</Tag>,
  },
  {
    title: 'CVSS',
    dataIndex: 'cvss_score',
    key: 'cvss_score',
    width: 160,
    sorter: (a, b) => a.cvss_score - b.cvss_score,
    render: (score: number) => (
      <Progress
        percent={score * 10}
        size="small"
        strokeColor={score >= 9 ? '#ff4d4f' : score >= 7 ? '#fa8c16' : score >= 4 ? '#fadb14' : '#1677ff'}
        format={() => score.toFixed(1)}
      />
    ),
  },
  {
    title: '发布日期',
    dataIndex: 'published',
    key: 'published',
    width: 120,
    render: (text: string) => text ? new Date(text).toLocaleDateString() : 'N/A',
  },
  {
    title: '摘要',
    dataIndex: 'description',
    key: 'description',
    ellipsis: true,
  },
];

export default function CveTable({ data, loading, total, page, pageSize, onPageChange, onRowClick }: Props) {
  return (
    <Table
      columns={columns}
      dataSource={data}
      rowKey="id"
      loading={loading}
      pagination={{
        current: page,
        pageSize,
        total,
        onChange: onPageChange,
        showSizeChanger: true,
        showTotal: (t) => `共 ${t} 条`,
      }}
      onRow={(record) => ({
        onClick: () => onRowClick(record),
        style: { cursor: 'pointer' },
      })}
      size="middle"
      scroll={{ x: 900 }}
    />
  );
}
