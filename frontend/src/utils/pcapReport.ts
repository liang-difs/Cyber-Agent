import type { PcapResult } from '../types/api';

export const PCAP_REPORT_STORAGE_KEY = 'cybersec:pcap-report-source';

export interface PcapReportSource {
  filename?: string;
  result: PcapResult;
  savedAt: number;
}

export function formatPcapReportTitle(filename?: string): string {
  return filename ? `PCAP 安全事件报告 - ${filename}` : 'PCAP 安全事件报告';
}

export function getPcapDisplayFilename(source?: PcapReportSource | null): string | undefined {
  if (!source?.result) return source?.filename;
  return source.result.pcap_identity?.display_filename
    || source.result.pcap_identity?.original_filename
    || source.filename;
}
