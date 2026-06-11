import { useEffect, useState, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Alert, Card, Form, Input, Button, Switch, Row, Col, message, Spin, Tabs, Upload } from 'antd';
import { DownloadOutlined, FileTextOutlined, UploadOutlined, PrinterOutlined } from '@ant-design/icons';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeSanitize from 'rehype-sanitize';
import { generateReport, generatePcapReport, generateReportHtml, generatePcapReportHtml, downloadReportPdf, downloadReportDocx, downloadPcapReportPdf, downloadPcapReportDocx } from '../../api/report';
import type { PcapResult } from '../../types/api';
import { formatPcapReportTitle, getPcapDisplayFilename, PCAP_REPORT_STORAGE_KEY, type PcapReportSource } from '../../utils/pcapReport';

const { TextArea } = Input;

export default function Reports() {
  const [searchParams] = useSearchParams();
  const [form] = Form.useForm();
  const [pcapForm] = Form.useForm();
  const [activeTab, setActiveTab] = useState(searchParams.get('source') === 'pcap' ? 'pcap' : 'standard');
  const [loading, setLoading] = useState(false);
  const [pcapLoading, setPcapLoading] = useState(false);
  const [markdown, setMarkdown] = useState<string>('');
  const [pcapMarkdown, setPcapMarkdown] = useState<string>('');
  const [pcapSource, setPcapSource] = useState<PcapReportSource | null>(null);

  useEffect(() => {
    const raw = sessionStorage.getItem(PCAP_REPORT_STORAGE_KEY);
    if (!raw) return;
    try {
      const source = JSON.parse(raw) as PcapReportSource;
      if (!source?.result) return;
      setPcapSource(source);
      setActiveTab('pcap');
      const displayFilename = getPcapDisplayFilename(source);
      pcapForm.setFieldsValue({
        title: formatPcapReportTitle(displayFilename),
        pcap_json: JSON.stringify(source.result, null, 2),
      });
    } catch {
      sessionStorage.removeItem(PCAP_REPORT_STORAGE_KEY);
    }
  }, [pcapForm]);

  const handleGenerate = useCallback(async () => {
    setLoading(true);
    try {
      const values = await form.validateFields();
      const md = await generateReport({
        title: values.title || 'Incident Report',
        analyst_notes: values.analyst_notes || '',
        include_raw_data: values.include_raw_data || false,
      });
      setMarkdown(md);
      message.success('报告生成成功');
    } catch (err: any) {
      if (err.response?.data?.detail) {
        message.error(err.response.data.detail);
      } else if (!err.errorFields) {
        message.error('生成失败');
      }
    } finally {
      setLoading(false);
    }
  }, [form]);

  const handlePcapGenerate = useCallback(async () => {
    setPcapLoading(true);
    try {
      const values = await pcapForm.validateFields();
      let pcapResult: PcapResult;
      try {
        pcapResult = JSON.parse(values.pcap_json);
      } catch {
        message.error('PCAP 结果 JSON 格式无效');
        setPcapLoading(false);
        return;
      }
      const md = await generatePcapReport({
        title: values.title || 'PCAP 安全事件报告',
        analyst_notes: values.analyst_notes || '',
        pcap_result: pcapResult as unknown as Record<string, unknown>,
      });
      setPcapMarkdown(md);
      message.success('PCAP 报告生成成功');
    } catch (err: any) {
      if (err.response?.data?.detail) {
        message.error(err.response.data.detail);
      } else if (!err.errorFields) {
        message.error('生成失败');
      }
    } finally {
      setPcapLoading(false);
    }
  }, [pcapForm]);

  const handlePcapFileUpload = useCallback((file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      pcapForm.setFieldsValue({ pcap_json: text });
      sessionStorage.removeItem(PCAP_REPORT_STORAGE_KEY);
      setPcapSource(null);
      message.success('文件已加载');
    };
    reader.readAsText(file);
    return false; // prevent default upload
  }, [pcapForm]);

  const handleClearPcapSource = useCallback(() => {
    sessionStorage.removeItem(PCAP_REPORT_STORAGE_KEY);
    setPcapSource(null);
    pcapForm.setFieldsValue({ pcap_json: undefined, title: 'PCAP 安全事件报告' });
    setPcapMarkdown('');
  }, [pcapForm]);

  const handleDownload = (md: string, filename: string) => {
    if (!md) return;
    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadHtml = async (type: 'standard' | 'pcap') => {
    try {
      let html: string;
      if (type === 'standard') {
        html = await generateReportHtml({
          title: form.getFieldValue('title') || 'Incident Report',
          time_window_hours: form.getFieldValue('time_window_hours'),
          analyst_notes: form.getFieldValue('analyst_notes'),
          include_raw_data: form.getFieldValue('include_raw_data'),
        });
      } else {
        const pcapJson = pcapForm.getFieldValue('pcap_json');
        let pcapResult: Record<string, any> = {};
        if (typeof pcapJson === 'string' && pcapJson.trim()) {
          try { pcapResult = JSON.parse(pcapJson); } catch { message.error('PCAP JSON 格式错误'); return; }
        } else if (typeof pcapJson === 'object' && pcapJson) {
          pcapResult = pcapJson;
        }
        html = await generatePcapReportHtml({
          title: pcapForm.getFieldValue('title') || 'PCAP 安全事件报告',
          analyst_notes: pcapForm.getFieldValue('analyst_notes'),
          pcap_result: pcapResult,
        });
      }
      const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      window.open(url, '_blank');
      message.success('已在新标签页打开，按 Ctrl+P 打印为 PDF');
    } catch (err: any) {
      message.error(err?.response?.data?.detail || '生成 HTML 报告失败');
    }
  };

  const renderReportPreview = (md: string, loadingState: boolean) => (
    <Card title="报告预览" style={{ width: '100%' }} bodyStyle={{ maxHeight: 'calc(100vh - 260px)', overflow: 'auto' }}>
      {loadingState && <Spin style={{ display: 'block', margin: '40px auto' }} />}
      {!loadingState && !md && (
        <div style={{ textAlign: 'center', padding: 80, color: '#aaa' }}>
          <FileTextOutlined style={{ fontSize: 48, marginBottom: 16 }} />
          <p>配置参数后点击"生成报告"</p>
        </div>
      )}
      {md && (
        <div className="markdown-body">
          <ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeSanitize]}>{md}</ReactMarkdown>
        </div>
      )}
    </Card>
  );

  return (
    <div className="page-shell" style={{ flexDirection: 'column' }}>
    <Tabs
      className="page-tabs-fill"
      style={{ flex: 1 }}
      activeKey={activeTab}
      onChange={setActiveTab}
      items={[
        {
          key: 'standard',
          label: '标准报告',
          children: (
            <Row gutter={[24, 16]} style={{ flex: 1, minHeight: 0 }}>
              <Col xs={24} lg={8} style={{ display: 'flex' }}>
                <Card title="报告配置" className="page-card-fill" style={{ width: '100%' }}>
                  <Form form={form} layout="vertical" initialValues={{ title: '安全事件报告' }}>
                    <Form.Item label="报告标题" name="title">
                      <Input placeholder="输入报告标题" />
                    </Form.Item>
                    <Form.Item label="分析师备注" name="analyst_notes">
                      <TextArea rows={4} placeholder="可选：添加分析师备注" />
                    </Form.Item>
                    <Form.Item label="包含原始数据" name="include_raw_data" valuePropName="checked">
                      <Switch />
                    </Form.Item>
                    <Form.Item>
                      <Button
                        type="primary"
                        icon={<FileTextOutlined />}
                        onClick={handleGenerate}
                        loading={loading}
                        block
                      >
                        生成报告
                      </Button>
                    </Form.Item>
                    {markdown && (
                      <>
                        <Button icon={<DownloadOutlined />} onClick={() => handleDownload(markdown, 'report.md')} block>
                          下载 Markdown
                        </Button>
                        <Button icon={<PrinterOutlined />} onClick={() => handleDownloadHtml('standard')} block style={{ marginTop: 8 }}>
                          导出 HTML (可打印PDF)
                        </Button>
                        <Button icon={<DownloadOutlined />} onClick={async () => {
                          try {
                            await downloadReportPdf({
                              title: form.getFieldValue('title') || 'Incident Report',
                              analyst_notes: form.getFieldValue('analyst_notes'),
                              include_raw_data: form.getFieldValue('include_raw_data'),
                            });
                            message.success('PDF 下载成功');
                          } catch { message.error('PDF 生成失败'); }
                        }} block style={{ marginTop: 8 }}>
                          下载 PDF
                        </Button>
                        <Button icon={<DownloadOutlined />} onClick={async () => {
                          try {
                            await downloadReportDocx({
                              title: form.getFieldValue('title') || 'Incident Report',
                              analyst_notes: form.getFieldValue('analyst_notes'),
                              include_raw_data: form.getFieldValue('include_raw_data'),
                            });
                            message.success('DOCX 下载成功');
                          } catch { message.error('DOCX 生成失败'); }
                        }} block style={{ marginTop: 8 }}>
                          下载 DOCX
                        </Button>
                      </>
                    )}
                  </Form>
                </Card>
              </Col>
              <Col xs={24} lg={16}>
                {renderReportPreview(markdown, loading)}
              </Col>
            </Row>
          ),
        },
        {
          key: 'pcap',
          label: 'PCAP 事件报告',
          children: (
            <Row gutter={[24, 16]} style={{ flex: 1, minHeight: 0 }}>
              <Col xs={24} lg={8} style={{ display: 'flex' }}>
                <Card title="PCAP 报告配置" className="page-card-fill" style={{ width: '100%' }}>
                  <Form form={pcapForm} layout="vertical" initialValues={{ title: 'PCAP 安全事件报告' }}>
                    {pcapSource && (
                      <Alert
                        type="success"
                        showIcon
                        style={{ marginBottom: 16 }}
                        message="已导入 PCAP 分析结果"
                        description={getPcapDisplayFilename(pcapSource) || '来自 PCAP 流量分析页面'}
                        action={
                          <Button size="small" onClick={handleClearPcapSource}>
                            清除
                          </Button>
                        }
                      />
                    )}
                    <Form.Item label="报告标题" name="title">
                      <Input placeholder="输入报告标题" />
                    </Form.Item>
                    <Form.Item label="分析师备注" name="analyst_notes">
                      <TextArea rows={2} placeholder="可选" />
                    </Form.Item>
                    <Form.Item label="PCAP 分析结果 (JSON)" name="pcap_json"
                      extra="优先从 PCAP 流量分析页自动导入，也支持粘贴 result JSON 或上传 JSON 文件">
                      <TextArea rows={6} placeholder='{"success": true, "summary": {...}, ...}' />
                    </Form.Item>
                    <Form.Item>
                      <Upload beforeUpload={handlePcapFileUpload} showUploadList={false} accept=".json" style={{ width: '100%' }}>
                        <Button icon={<UploadOutlined />} block>
                          导入 JSON 文件
                        </Button>
                      </Upload>
                    </Form.Item>
                    <Form.Item>
                      <Button
                        type="primary"
                        icon={<FileTextOutlined />}
                        onClick={handlePcapGenerate}
                        loading={pcapLoading}
                        block
                      >
                        生成 PCAP 报告
                      </Button>
                    </Form.Item>
                    {pcapMarkdown && (
                      <>
                        <Button icon={<DownloadOutlined />} onClick={() => handleDownload(pcapMarkdown, 'pcap-report.md')} block>
                          下载 Markdown
                        </Button>
                        <Button icon={<PrinterOutlined />} onClick={() => handleDownloadHtml('pcap')} block style={{ marginTop: 8 }}>
                          导出 HTML (可打印PDF)
                        </Button>
                        <Button icon={<DownloadOutlined />} onClick={async () => {
                          try {
                            const pcapJson = pcapForm.getFieldValue('pcap_json');
                            let pcapResult: Record<string, any> = {};
                            if (typeof pcapJson === 'string' && pcapJson.trim()) {
                              try { pcapResult = JSON.parse(pcapJson); } catch { message.error('PCAP JSON 格式错误'); return; }
                            }
                            await downloadPcapReportPdf({
                              title: pcapForm.getFieldValue('title') || 'PCAP 安全事件报告',
                              analyst_notes: pcapForm.getFieldValue('analyst_notes'),
                              pcap_result: pcapResult,
                            });
                            message.success('PDF 下载成功');
                          } catch { message.error('PDF 生成失败'); }
                        }} block style={{ marginTop: 8 }}>
                          下载 PDF
                        </Button>
                        <Button icon={<DownloadOutlined />} onClick={async () => {
                          try {
                            const pcapJson = pcapForm.getFieldValue('pcap_json');
                            let pcapResult: Record<string, any> = {};
                            if (typeof pcapJson === 'string' && pcapJson.trim()) {
                              try { pcapResult = JSON.parse(pcapJson); } catch { message.error('PCAP JSON 格式错误'); return; }
                            }
                            await downloadPcapReportDocx({
                              title: pcapForm.getFieldValue('title') || 'PCAP 安全事件报告',
                              analyst_notes: pcapForm.getFieldValue('analyst_notes'),
                              pcap_result: pcapResult,
                            });
                            message.success('DOCX 下载成功');
                          } catch { message.error('DOCX 生成失败'); }
                        }} block style={{ marginTop: 8 }}>
                          下载 DOCX
                        </Button>
                      </>
                    )}
                  </Form>
                </Card>
              </Col>
              <Col xs={24} lg={16}>
                {renderReportPreview(pcapMarkdown, pcapLoading)}
              </Col>
            </Row>
          ),
        },
      ]}
    />
    </div>
  );
}
