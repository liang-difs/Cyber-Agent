import client from './client';

export interface IoCResultItem {
  indicator: string;
  ioc_type: string;
  success: boolean;
  risk_level?: string;
  data?: Record<string, any>;
  error?: string;
}

export interface BulkIoCResponse {
  results: IoCResultItem[];
  total: number;
  success_count: number;
}

export async function bulkIoCLookup(indicators: string[], maxConcurrent = 5): Promise<BulkIoCResponse> {
  const { data } = await client.post<BulkIoCResponse>('/ioc/bulk-lookup', {
    indicators,
    max_concurrent: maxConcurrent,
  });
  return data;
}
