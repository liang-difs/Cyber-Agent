import client from './client';
import type { AttackChainResponse, CorrelationResponse } from '../types/api';

export async function getAttackChains(params?: {
  time_window_hours?: number;
  min_chain_length?: number;
  src_ip?: string;
  status?: string;
}): Promise<AttackChainResponse> {
  const { data } = await client.post<AttackChainResponse>('/analysis/attack-chains', params || {});
  return data;
}

export async function correlateAlerts(params?: {
  burst_window_minutes?: number;
  burst_threshold?: number;
  src_ip?: string;
}): Promise<CorrelationResponse> {
  const { data } = await client.post<CorrelationResponse>('/analysis/correlate', params || {});
  return data;
}
