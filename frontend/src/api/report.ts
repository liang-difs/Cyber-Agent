import client from './client';

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
  pcap_result: Record<string, any>;
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
  pcap_result: Record<string, any>;
}): Promise<string> {
  const { data } = await client.post('/reports/generate-pcap?format=html', params, {
    responseType: 'text',
  });
  return data as unknown as string;
}

export async function downloadReportPdf(params: {
  title?: string;
  time_window_hours?: number;
  analyst_notes?: string;
  include_raw_data?: boolean;
  src_ip?: string;
}, filename?: string): Promise<void> {
  const { data } = await client.post('/reports/generate?format=pdf', params, {
    responseType: 'blob',
  });
  const blob = new Blob([data], { type: 'application/pdf' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename || 'report.pdf';
  a.click();
  URL.revokeObjectURL(url);
}

export async function downloadReportDocx(params: {
  title?: string;
  time_window_hours?: number;
  analyst_notes?: string;
  include_raw_data?: boolean;
  src_ip?: string;
}, filename?: string): Promise<void> {
  const { data } = await client.post('/reports/generate?format=docx', params, {
    responseType: 'blob',
  });
  const blob = new Blob([data], { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename || 'report.docx';
  a.click();
  URL.revokeObjectURL(url);
}

export async function downloadPcapReportPdf(params: {
  title?: string;
  time_window_hours?: number;
  analyst_notes?: string;
  pcap_result: Record<string, any>;
}, filename?: string): Promise<void> {
  const { data } = await client.post('/reports/generate-pcap?format=pdf', params, {
    responseType: 'blob',
  });
  const blob = new Blob([data], { type: 'application/pdf' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename || 'pcap-report.pdf';
  a.click();
  URL.revokeObjectURL(url);
}

export async function downloadPcapReportDocx(params: {
  title?: string;
  time_window_hours?: number;
  analyst_notes?: string;
  pcap_result: Record<string, any>;
}, filename?: string): Promise<void> {
  const { data } = await client.post('/reports/generate-pcap?format=docx', params, {
    responseType: 'blob',
  });
  const blob = new Blob([data], { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename || 'pcap-report.docx';
  a.click();
  URL.revokeObjectURL(url);
}
