import client from './client';
import type { Asset } from '../types/api';

export interface AssetListResponse {
  assets: Asset[];
  total: number;
  limit: number;
  offset: number;
}

export async function listAssets(params?: {
  asset_type?: string;
  criticality?: string;
  status?: string;
  keyword?: string;
  limit?: number;
  offset?: number;
}): Promise<AssetListResponse> {
  const { data } = await client.get<AssetListResponse>('/assets', { params });
  return data;
}

export async function createAsset(body: {
  name: string;
  asset_type?: string;
  ip_address?: string;
  hostname?: string;
  os?: string;
  owner?: string;
  department?: string;
  criticality?: string;
  tags?: string[];
  notes?: string;
}): Promise<Asset> {
  const { data } = await client.post<Asset>('/assets', body);
  return data;
}

export async function updateAsset(id: string, body: Partial<Asset>): Promise<Asset> {
  const { data } = await client.patch<Asset>(`/assets/${id}`, body);
  return data;
}

export async function deleteAsset(id: string): Promise<void> {
  await client.delete(`/assets/${id}`);
}
