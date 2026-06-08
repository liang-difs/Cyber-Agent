import { useState, useEffect, useCallback } from 'react';
import { Input, Select, Space, Row, Col, message } from 'antd';
import { SearchOutlined } from '@ant-design/icons';
import { listCves, getCveStats, getCve } from '../../api/cve';
import type { CveItem, CveStatsResponse, CveListResponse } from '../../types/api';
import CveTable from './CveTable';
import CveDetail from './CveDetail';
import StatsPanel from './StatsPanel';

const { Search } = Input;

const severityOptions = [
  { label: '全部', value: '' },
  { label: 'CRITICAL', value: 'CRITICAL' },
  { label: 'HIGH', value: 'HIGH' },
  { label: 'MEDIUM', value: 'MEDIUM' },
  { label: 'LOW', value: 'LOW' },
];

export default function CveSearch() {
  const [keyword, setKeyword] = useState('');
  const [severity, setSeverity] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [listData, setListData] = useState<CveListResponse | null>(null);
  const [stats, setStats] = useState<CveStatsResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [statsLoading, setStatsLoading] = useState(false);
  const [selectedCve, setSelectedCve] = useState<CveItem | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listCves({
        page,
        page_size: pageSize,
        severity: severity || undefined,
        keyword: keyword || undefined,
      });
      setListData(data);
    } catch {
      message.error('查询失败');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, severity, keyword]);

  const fetchStats = useCallback(async () => {
    setStatsLoading(true);
    try {
      const data = await getCveStats();
      setStats(data);
    } catch {
      // silent
    } finally {
      setStatsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  const handleSearch = (value: string) => {
    setKeyword(value);
    setPage(1);
  };

  const handleRowClick = async (record: CveItem) => {
    try {
      const detail = await getCve(record.cve_id);
      setSelectedCve(detail);
      setDrawerOpen(true);
    } catch {
      message.error('获取详情失败');
    }
  };

  return (
    <div className="page-shell" style={{ flexDirection: 'column', gap: 16 }}>
      <Row gutter={[16, 16]} style={{ flex: 1, minHeight: 0, alignItems: 'stretch' }}>
        <Col xs={24} xl={16}>
          <Space style={{ marginBottom: 16, width: '100%' }} size="middle" wrap>
            <Search
              placeholder="输入 CVE ID 或关键词"
              onSearch={handleSearch}
              style={{ width: 'min(100%, 360px)' }}
              enterButton={<SearchOutlined />}
              allowClear
            />
            <Select
              value={severity}
              onChange={(v) => { setSeverity(v); setPage(1); }}
              options={severityOptions}
              style={{ width: 140 }}
              placeholder="严重程度"
            />
          </Space>
          <CveTable
            data={listData?.items || []}
            loading={loading}
            total={listData?.total || 0}
            page={page}
            pageSize={pageSize}
            onPageChange={(p, ps) => { setPage(p); setPageSize(ps); }}
            onRowClick={handleRowClick}
          />
        </Col>
        <Col xs={24} xl={8}>
          <div style={{ height: '100%' }}>
            <StatsPanel stats={stats} loading={statsLoading} />
          </div>
        </Col>
      </Row>
      <CveDetail cve={selectedCve} open={drawerOpen} onClose={() => setDrawerOpen(false)} />
    </div>
  );
}
