import client from './client';
import type { CveListResponse, CveStatsResponse, CveItem } from '../types/api';

export async function listCves(params: {
  page?: number;
  page_size?: number;
  severity?: string;
  keyword?: string;
}): Promise<CveListResponse> {
  const { data } = await client.get<CveListResponse>('/cve/list', { params });
  return data;
}

export async function getCve(cveId: string): Promise<CveItem> {
  const { data } = await client.get<CveItem>(`/cve/${cveId}`);
  return data;
}

export async function getCveStats(): Promise<CveStatsResponse> {
  const { data } = await client.get<CveStatsResponse>('/cve/stats');
  return data;
}
