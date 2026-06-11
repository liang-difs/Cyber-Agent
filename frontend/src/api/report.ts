import client from './client';
import { downloadBlob } from '../utils/helpers';

export async function generateReport(params: {
  title?: string;
  time_window_hours?: number;
  analyst_notes?: string;
  include_raw_data?: boolean;
  src_ip?: string;
}): Promise<string> {
  const { data } = await client.post('/reports/generate', params, {
    responseType: 'text',
  });
  return data as unknown as string;
}

export async function generatePcapReport(params: {
  title?: string;
  time_window_hours?: number;
  analyst_notes?: string;
  pcap_result: Record<string, unknown>;
}): Promise<string> {
  const { data } = await client.post('/reports/generate-pcap', params, {
    responseType: 'text',
  });
  return data as unknown as string;
}

export async function generateReportHtml(params: {
  title?: string;
  time_window_hours?: number;
  analyst_notes?: string;
  include_raw_data?: boolean;
  src_ip?: string;
}): Promise<string> {
  const { data } = await client.post('/reports/generate?format=html', params, {
    responseType: 'text',
  });
  return data as unknown as string;
}

export async function generatePcapReportHtml(params: {
  title?: string;
  time_window_hours?: number;
  analyst_notes?: string;
  pcap_result: Record<string, unknown>;
}): Promise<string> {
  const { data } = await client.post('/reports/generate-pcap?format=html', params, {
    responseType: 'text',
  });
  return data as unknown as string;
}

type ReportParams = {
  title?: string;
  time_window_hours?: number;
  analyst_notes?: string;
  include_raw_data?: boolean;
  src_ip?: string;
};

type PcapReportParams = {
  title?: string;
  time_window_hours?: number;
  analyst_notes?: string;
  pcap_result: Record<string, unknown>;
};

async function downloadReport(
  endpoint: string,
  params: ReportParams | PcapReportParams,
  format: 'pdf' | 'docx',
  defaultFilename: string,
  filename?: string,
): Promise<void> {
  const { data } = await client.post(`${endpoint}?format=${format}`, params, {
    responseType: 'blob',
  });
  const mimeType = format === 'pdf'
    ? 'application/pdf'
    : 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
  const blob = new Blob([data], { type: mimeType });
  downloadBlob(blob, filename || defaultFilename);
}

export function downloadReportPdf(params: ReportParams, filename?: string): Promise<void> {
  return downloadReport('/reports/generate', params, 'pdf', 'report.pdf', filename);
}

export function downloadReportDocx(params: ReportParams, filename?: string): Promise<void> {
  return downloadReport('/reports/generate', params, 'docx', 'report.docx', filename);
}

export function downloadPcapReportPdf(params: PcapReportParams, filename?: string): Promise<void> {
  return downloadReport('/reports/generate-pcap', params, 'pdf', 'pcap-report.pdf', filename);
}

export function downloadPcapReportDocx(params: PcapReportParams, filename?: string): Promise<void> {
  return downloadReport('/reports/generate-pcap', params, 'docx', 'pcap-report.docx', filename);
}
