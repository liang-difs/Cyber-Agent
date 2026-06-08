import { useState, useCallback, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Upload, Card, Row, Col, Statistic, Tabs, Table, Tag, Progress, message, Spin, Button, Alert, Steps, Space, Collapse } from 'antd';
import {
  InboxOutlined,
  CheckCircleFilled,
  CloseCircleFilled,
  ReloadOutlined,
  CloudUploadOutlined,
  LoadingOutlined,
  FileSearchOutlined,
  CopyOutlined,
  FileTextOutlined,
  FolderOutlined,
} from '@ant-design/icons';
import ReactECharts from 'echarts-for-react';
import { uploadPcap, listPcapFiles, type PcapFileInfo } from '../../api/task';
import { useTaskPolling } from '../../hooks/useTaskPolling';
import type { PcapResult, PcapAnomaly, PcapFlow, TimelineEvent, TaskStatus } from '../../types/api';
import { getPcapDisplayFilename, PCAP_REPORT_STORAGE_KEY, type PcapReportSource } from '../../utils/pcapReport';

const { Dragger } = Upload;

import { SEVERITY_TAG_COLORS as SEVERITY_COLORS } from '../../constants/severity';

const ANOMALY_COLUMNS = [
  {
    title: '类型', dataIndex: 'type', key: 'type',
    render: (v: string) => <Tag color="red">{v}</Tag>,
  },
  {
    title: '严重程度', dataIndex: 'severity', key: 'severity',
    render: (v: string) => <Tag color={SEVERITY_COLORS[v] || 'default'}>{(v || 'medium').toUpperCase()}</Tag>,
  },
  { title: '源 IP', dataIndex: 'src_ip', key: 'src_ip', render: (v: string) => v || '-' },
  { title: '目标 IP', dataIndex: 'dst_ip', key: 'dst_ip', render: (v: string) => v || '-' },
  { title: '详情', dataIndex: 'detail', key: 'detail', ellipsis: true },
];

const FLOW_COLUMNS = [
  { title: '源 IP', dataIndex: 'src_ip', key: 'src_ip', width: 130 },
  { title: '源端口', dataIndex: 'src_port', key: 'src_port', width: 70, render: (v: number | null) => v ?? '-' },
  { title: '目标 IP', dataIndex: 'dst_ip', key: 'dst_ip', width: 130 },
  { title: '目标端口', dataIndex: 'dst_port', key: 'dst_port', width: 80, render: (v: number | null) => v ?? '-' },
  { title: '协议', dataIndex: 'app_protocol', key: 'app_protocol', width: 70 },
  {
    title: '方向', dataIndex: 'direction', key: 'direction', width: 80,
    render: (v: string) => {
      const colors: Record<string, string> = { outbound: 'orange', inbound: 'blue', internal: 'green' };
      return <Tag color={colors[v] || 'default'}>{v}</Tag>;
    },
  },
  { title: '包数', dataIndex: 'packets', key: 'packets', width: 70, sorter: (a: PcapFlow, b: PcapFlow) => a.packets - b.packets },
  {
    title: '字节数', dataIndex: 'bytes', key: 'bytes', width: 90,
    render: (v: number) => v > 1024 * 1024 ? `${(v / 1024 / 1024).toFixed(1)} MB` : v > 1024 ? `${(v / 1024).toFixed(1)} KB` : `${v} B`,
    sorter: (a: PcapFlow, b: PcapFlow) => a.bytes - b.bytes,
    defaultSortOrder: 'descend' as const,
  },
  { title: '时长', dataIndex: 'duration_s', key: 'duration_s', width: 70, render: (v: number) => `${v}s` },
  {
    title: 'TCP 标志', key: 'tcp_flags', width: 120,
    render: (_: any, record: PcapFlow) => {
      const f = record.tcp_flags;
      if (!f) return '-';
      const parts = [];
      if (f.SYN) parts.push(<Tag key="S" color="blue">SYN:{f.SYN}</Tag>);
      if (f.ACK) parts.push(<Tag key="A" color="green">ACK:{f.ACK}</Tag>);
      if (f.RST) parts.push(<Tag key="R" color="red">RST:{f.RST}</Tag>);
      if (f.FIN) parts.push(<Tag key="F" color="default">FIN:{f.FIN}</Tag>);
      return parts.length ? parts : '-';
    },
  },
];

const DNS_COLUMNS = [
  { title: '域名', dataIndex: 'name', key: 'name', ellipsis: true },
  { title: '类型', dataIndex: 'type', key: 'type', width: 70, render: (v: string) => <Tag color="purple">{v}</Tag> },
  { title: '应答', dataIndex: 'response', key: 'response', width: 130, render: (v: string) => v || '-' },
  { title: '来源 IP', dataIndex: 'src_ip', key: 'src_ip', width: 130 },
  {
    title: '时间', dataIndex: 'timestamp', key: 'timestamp', width: 160,
    render: (v: number) => v ? new Date(v * 1000).toLocaleString('zh-CN') : '-',
  },
];

const TIMELINE_COLUMNS = [
  {
    title: '时间', dataIndex: 'timestamp', key: 'timestamp', width: 160,
    render: (v: number) => v ? new Date(v * 1000).toLocaleString('zh-CN') : '-',
    sorter: (a: TimelineEvent, b: TimelineEvent) => a.timestamp - b.timestamp,
  },
  {
    title: '类型', dataIndex: 'event_type', key: 'event_type', width: 100,
    render: (v: string) => {
      const colors: Record<string, string> = { new_flow: 'blue', anomaly: 'red', dns_query: 'purple' };
      const labels: Record<string, string> = { new_flow: '新流', anomaly: '异常', dns_query: 'DNS' };
      return <Tag color={colors[v] || 'default'}>{labels[v] || v}</Tag>;
    },
  },
  { title: '源 IP', dataIndex: 'src_ip', key: 'src_ip', width: 130 },
  { title: '详情', dataIndex: 'detail', key: 'detail', ellipsis: true },
];

type StepStatus = 'wait' | 'process' | 'finish' | 'error';

export default function PcapAnalysis() {
  const navigate = useNavigate();
  const [uploading, setUploading] = useState(false);
  const [taskStatus, setTaskStatus] = useState<string | null>(null);
  const [result, setResult] = useState<PcapResult | null>(null);
  const [filename, setFilename] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [progressPercent, setProgressPercent] = useState(0);
  const [pcapFiles, setPcapFiles] = useState<PcapFileInfo[]>([]);
  const [pcapTotalSize, setPcapTotalSize] = useState(0);
  const { polling, pollTask: pollTaskStatus, cancel } = useTaskPolling();

  const fetchPcapFiles = useCallback(async () => {
    try {
      const resp = await listPcapFiles();
      setPcapFiles(resp?.files || []);
      setPcapTotalSize(resp?.total_size_bytes || 0);
    } catch { /* silent */ }
  }, []);

  useEffect(() => { fetchPcapFiles(); }, [fetchPcapFiles]);

  const pollPcapTask = useCallback(async (tid: string) => {
    setProgressPercent(10);
    try {
      const status = await pollTaskStatus(tid, {
        maxAttempts: 120,
        intervalMs: 2000,
        onStatus: (s: TaskStatus, attempt: number) => {
          setTaskStatus(s.status);
          setProgressPercent(Math.min(10 + (attempt / 120) * 80, 90));
        },
      });
      if (status.status === 'SUCCESS' || status.status === 'SUCCEEDED') {
        setResult(status.result as PcapResult);
        setProgressPercent(100);
        message.success('分析完成');
        return;
      }
      if (status.status === 'FAILURE' || status.status === 'FAILED') {
        setError(status.traceback || String(status.result) || '未知错误');
        return;
      }
      if (status.warning) {
        setError('Celery worker 未运行，任务无法执行。');
        return;
      }
    } catch (err: any) {
      setError(err.message || '轮询失败');
    }
  }, [pollTaskStatus]);

  const handleUpload = useCallback(async (file: File) => {
    const ext = file.name.split('.').pop()?.toLowerCase();
    if (ext !== 'pcap' && ext !== 'pcapng') { message.error('仅支持 .pcap/.pcapng'); return false; }
    if (file.size > 2 * 1024 * 1024 * 1024) { message.error('文件过大'); return false; }

    setUploading(true);
    setFilename(file.name);
    setResult(null);
    setError(null);
    setProgressPercent(5);
    try {
      const resp = await uploadPcap(file);
      setTaskStatus(resp.status);
      if (resp.sync && resp.result) {
        setResult(resp.result);
        setProgressPercent(100);
        message.success('分析完成（同步模式）');
      } else {
        setTaskStatus('PENDING');
        pollPcapTask(resp.task_id);
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || '上传失败');
    } finally {
      setUploading(false);
    }
    return false;
  }, [pollPcapTask]);

  const handleReset = () => {
    cancel();
    setResult(null);
    setError(null);
    setProgressPercent(0);
    setFilename('');
  };

  const copyResultJson = async () => {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(result, null, 2));
      message.success('分析结果 JSON 已复制');
    } catch {
      message.error('复制失败，请从“原始数据”页签手动复制');
    }
  };

  const openPcapReport = () => {
    if (!result) return;
    try {
      const payload: PcapReportSource = {
        filename: getPcapDisplayFilename({ filename, result, savedAt: Date.now() }) || filename,
        result,
        savedAt: Date.now(),
      };
      sessionStorage.setItem(PCAP_REPORT_STORAGE_KEY, JSON.stringify(payload));
      navigate('/reports?source=pcap');
    } catch {
      message.error('结果过大，无法暂存到报告页，请复制 JSON 后在报告页导入');
    }
  };

  const protocolChartOption = result?.protocols
    ? {
        tooltip: { trigger: 'item' as const },
        series: [{
          type: 'pie',
          radius: ['40%', '70%'],
          data: Object.entries(result.protocols).map(([name, value]) => ({ name, value })),
        }],
      }
    : null;

  const dnsTypeChartOption = result?.dns?.stats?.query_types
    ? {
        tooltip: { trigger: 'item' as const },
        series: [{
          type: 'pie',
          radius: ['40%', '70%'],
          data: Object.entries(result.dns.stats.query_types).map(([name, value]) => ({ name, value })),
        }],
      }
    : null;

  const currentStep: number = uploading ? 0 : polling ? 1 : result ? 2 : 0;
  const stepStatus: StepStatus = error ? 'error' : result ? 'finish' : (uploading || polling) ? 'process' : 'wait';

  const summary = result?.summary;

  return (
    <div className="page-shell" style={{ flexDirection: 'column' }}>
      <Card
        title="PCAP 流量分析"
        className="page-card-fill"
        style={{ display: 'flex', flexDirection: 'column' }}
        extra={result && (
          <Space wrap>
            <Button icon={<CopyOutlined />} onClick={copyResultJson}>复制 JSON</Button>
            <Button type="primary" icon={<FileTextOutlined />} onClick={openPcapReport}>生成报告</Button>
            <Button icon={<ReloadOutlined />} onClick={handleReset}>重新上传</Button>
          </Space>
        )}
      >
        {!result && !polling && !uploading && (
          <Dragger accept=".pcap,.pcapng" showUploadList={false} beforeUpload={handleUpload} style={{ marginBottom: 24 }}>
            <p className="ant-upload-drag-icon"><InboxOutlined /></p>
            <p className="ant-upload-text">点击或拖拽 .pcap / .pcapng 文件到此区域</p>
            <p className="ant-upload-hint">最大支持 2GB</p>
          </Dragger>
        )}

        {!result && !polling && !uploading && pcapFiles.length > 0 && (
          <Collapse
            size="small"
            style={{ marginBottom: 16 }}
          >
            <Collapse.Panel
              header={<Space><FolderOutlined />历史文件 ({pcapFiles.length} 个, {(pcapTotalSize / 1024 / 1024).toFixed(1)} MB)</Space>}
              key="files"
            >
              <Table
                dataSource={pcapFiles}
                rowKey="filename"
                size="small"
                pagination={false}
                columns={[
                  { title: '文件名', dataIndex: 'filename', key: 'filename', ellipsis: true },
                  { title: '大小', dataIndex: 'size_bytes', key: 'size', width: 100, render: (v: number) => v > 1048576 ? `${(v / 1048576).toFixed(1)} MB` : `${(v / 1024).toFixed(0)} KB` },
                  { title: '上传时间', dataIndex: 'created_at', key: 'created_at', width: 180, render: (v: string) => new Date(v).toLocaleString('zh-CN') },
                ]}
              />
            </Collapse.Panel>
          </Collapse>
        )}

        {(uploading || polling) && (
          <div style={{ padding: '40px 80px' }}>
            <Steps current={currentStep} status={stepStatus} items={[
              { title: '上传文件', icon: uploading ? <LoadingOutlined /> : <CloudUploadOutlined /> },
              { title: '分析中', icon: polling ? <LoadingOutlined /> : <FileSearchOutlined /> },
              { title: '完成', icon: <CheckCircleFilled /> },
            ]} />
            <div style={{ textAlign: 'center', marginTop: 32 }}>
              <Spin size="large" />
              <Progress percent={progressPercent} status="active" style={{ maxWidth: 400, margin: '16px auto 0' }} />
              <p style={{ marginTop: 8, color: '#888' }}>{uploading ? '正在上传...' : `正在分析 (${taskStatus || 'PENDING'})...`}</p>
              <p style={{ color: '#aaa' }}>{filename}</p>
            </div>
          </div>
        )}

        {error && (
          <Alert type="error" showIcon message="分析失败" description={error} style={{ marginBottom: 16 }}
            action={<Button size="small" onClick={handleReset}>重试</Button>} />
        )}

        {result && result.success !== false && summary && (
          <>
            <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
              <Col xs={12} sm={8} lg={4}><Statistic title="总包数" value={summary.total_packets} /></Col>
              <Col xs={12} sm={8} lg={4}><Statistic title="流记录数" value={summary.total_flows} /></Col>
              <Col xs={12} sm={8} lg={4}><Statistic title="时长 (秒)" value={summary.duration_s} /></Col>
              <Col xs={12} sm={8} lg={4}>
                <Statistic title="总字节数"
                  value={summary.total_bytes > 1024 * 1024 ? `${(summary.total_bytes / 1024 / 1024).toFixed(1)} MB` : `${(summary.total_bytes / 1024).toFixed(1)} KB`} />
              </Col>
              <Col xs={12} sm={8} lg={4}>
                <Statistic title="异常数" value={summary.anomaly_count}
                  valueStyle={{ color: summary.anomaly_count > 0 ? '#cf1322' : '#3f8600' }} />
              </Col>
              <Col xs={12} sm={8} lg={4}><Statistic title="协议数" value={result.protocols ? Object.keys(result.protocols).length : 0} /></Col>
            </Row>

            {result.warning && <Alert type="warning" showIcon message={result.warning} style={{ marginBottom: 16 }} />}

            <Tabs items={[
              {
                key: 'anomalies',
                label: `异常检测 (${result.anomalies?.length ?? 0})`,
                children: <Table dataSource={result.anomalies || []} columns={ANOMALY_COLUMNS} rowKey={(_, i) => String(i)} pagination={false} size="small" />,
              },
              {
                key: 'flows',
                label: `流记录 (${result.flows?.length ?? 0})`,
                children: <Table dataSource={result.flows || []} columns={FLOW_COLUMNS} rowKey={(_, i) => String(i)} pagination={{ pageSize: 20 }} size="small" scroll={{ x: 1100 }} />,
              },
              {
                key: 'dns',
                label: `DNS 分析 (${result.dns?.stats?.total_queries ?? 0})`,
                children: (
                  <>
                    <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
                      <Col xs={12} md={6}><Statistic title="总查询数" value={result.dns?.stats?.total_queries ?? 0} /></Col>
                      <Col xs={12} md={6}><Statistic title="唯一域名" value={result.dns?.stats?.unique_domains ?? 0} /></Col>
                      <Col xs={12} md={6}>
                        <Statistic title="超长子域名" value={result.dns?.stats?.long_subdomains?.length ?? 0}
                          valueStyle={{ color: (result.dns?.stats?.long_subdomains?.length ?? 0) > 0 ? '#cf1322' : undefined }} />
                      </Col>
                      <Col xs={12} md={6}>
                        <Statistic title="TXT 查询" value={result.dns?.stats?.txt_queries?.length ?? 0}
                          valueStyle={{ color: (result.dns?.stats?.txt_queries?.length ?? 0) > 20 ? '#cf1322' : undefined }} />
                      </Col>
                    </Row>
                    {dnsTypeChartOption && (
                      <Card title="查询类型分布" size="small" style={{ marginBottom: 16 }}>
                        <ReactECharts option={dnsTypeChartOption} style={{ height: 250 }} />
                      </Card>
                    )}
                    {result.dns?.stats?.top_domains && result.dns.stats.top_domains.length > 0 && (
                      <Card title="高频域名" size="small" style={{ marginBottom: 16 }}>
                        {result.dns.stats.top_domains.map((d) => (
                          <Tag key={d.domain} color="purple" style={{ marginBottom: 4 }}>{d.domain} ({d.count})</Tag>
                        ))}
                      </Card>
                    )}
                    {result.dns?.stats?.high_frequency && result.dns.stats.high_frequency.length > 0 && (
                      <Alert type="warning" showIcon style={{ marginBottom: 16 }}
                        message={`高频查询: ${result.dns.stats.high_frequency.map(h => `${h.domain} (${h.count}次/${h.window_s}s)`).join(', ')}`} />
                    )}
                    <Table dataSource={result.dns?.queries || []} columns={DNS_COLUMNS} rowKey={(_, i) => String(i)} pagination={{ pageSize: 20 }} size="small" />
                  </>
                ),
              },
              {
                key: 'protocols',
                label: '协议分布',
                children: protocolChartOption ? <ReactECharts option={protocolChartOption} style={{ height: 350 }} /> : <p>无数据</p>,
              },
              {
                key: 'insights',
                label: '协议深度',
                children: (
                  <>
                    {result.protocol_insights?.http_hosts && result.protocol_insights.http_hosts.length > 0 && (
                      <Card title="HTTP Host" size="small" style={{ marginBottom: 16 }}>
                        <Table
                          dataSource={result.protocol_insights.http_hosts}
                          columns={[
                            { title: 'Host', dataIndex: 'host', key: 'host' },
                            { title: '次数', dataIndex: 'count', key: 'count', width: 70 },
                            { title: '方法', dataIndex: 'methods', key: 'methods', render: (v: string[]) => v?.join(', ') || '-' },
                          ]}
                          rowKey="host" pagination={false} size="small"
                        />
                      </Card>
                    )}
                    {result.protocol_insights?.tls_sni && result.protocol_insights.tls_sni.length > 0 && (
                      <Card title="TLS SNI" size="small" style={{ marginBottom: 16 }}>
                        <Table
                          dataSource={result.protocol_insights.tls_sni}
                          columns={[
                            { title: 'Server Name', dataIndex: 'server_name', key: 'server_name' },
                            { title: '次数', dataIndex: 'count', key: 'count', width: 70 },
                            { title: 'TLS 版本', dataIndex: 'tls_versions', key: 'ver', render: (v: string[]) => v?.join(', ') || '-' },
                          ]}
                          rowKey="server_name" pagination={false} size="small"
                        />
                      </Card>
                    )}
                    {result.protocol_insights?.tls_versions && Object.keys(result.protocol_insights.tls_versions).length > 0 && (
                      <Card title="TLS 版本分布" size="small" style={{ marginBottom: 16 }}>
                        {Object.entries(result.protocol_insights.tls_versions).map(([ver, count]) => {
                          const isWeak = ['SSLv3', 'TLSv1.0', 'TLSv1.1'].includes(ver) || ver.startsWith('0x030');
                          return <Tag key={ver} color={isWeak ? 'red' : 'green'} style={{ marginBottom: 4 }}>{ver}: {count}</Tag>;
                        })}
                      </Card>
                    )}
                    {result.protocol_insights?.ssh_versions && result.protocol_insights.ssh_versions.length > 0 && (
                      <Card title="SSH 版本" size="small">
                        {result.protocol_insights.ssh_versions.map((v) => <Tag key={v} style={{ marginBottom: 4 }}>{v}</Tag>)}
                      </Card>
                    )}
                    {!result.protocol_insights?.http_hosts?.length && !result.protocol_insights?.tls_sni?.length && <p>无协议深度数据</p>}
                  </>
                ),
              },
              {
                key: 'timeline',
                label: `时间线 (${result.timeline?.length ?? 0})`,
                children: <Table dataSource={result.timeline || []} columns={TIMELINE_COLUMNS} rowKey={(_, i) => String(i)} pagination={{ pageSize: 50 }} size="small" />,
              },
              {
                key: 'ips',
                label: 'IP 概览',
                children: (
                  <Row gutter={[24, 16]}>
                    <Col xs={24} md={8}>
                      <Card title="外部 IP" size="small">
                        {result.ips?.external_ips?.map((ip) => <Tag key={ip} color="orange" style={{ marginBottom: 4 }}>{ip}</Tag>) || '无'}
                      </Card>
                    </Col>
                    <Col xs={24} md={8}>
                      <Card title="内部 IP" size="small">
                        {result.ips?.internal_ips?.map((ip) => <Tag key={ip} color="blue" style={{ marginBottom: 4 }}>{ip}</Tag>) || '无'}
                      </Card>
                    </Col>
                    <Col xs={24} md={8}>
                      <Card title="全部目标 IP" size="small">
                        {result.ips?.destination_ips?.map((ip) => <Tag key={ip} color="green" style={{ marginBottom: 4 }}>{ip}</Tag>) || '无'}
                      </Card>
                    </Col>
                  </Row>
                ),
              },
              {
                key: 'raw',
                label: '原始数据',
                children: <pre style={{ maxHeight: 500, overflow: 'auto', background: 'var(--app-code-bg)', color: 'var(--app-text)', padding: 16, borderRadius: 8, fontSize: 12 }}>{JSON.stringify(result, null, 2)}</pre>,
              },
            ]} />
          </>
        )}

        {result && result.success === false && (
          <Alert
            type="error"
            showIcon
            icon={<CloseCircleFilled />}
            message="PCAP 分析失败"
            description={result.error || result.warning || '任务已返回失败状态，但未提供具体错误信息。'}
            action={
              <Space>
                <Button size="small" icon={<CopyOutlined />} onClick={copyResultJson}>复制结果</Button>
                <Button size="small" onClick={handleReset}>重新上传</Button>
              </Space>
            }
          />
        )}
      </Card>
    </div>
  );
}
