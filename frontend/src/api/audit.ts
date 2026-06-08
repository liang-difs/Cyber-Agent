import client from './client';
import type { AuditLogResponse } from '../types/api';

export async function getAuditLogs(params?: {
  user_id?: string;
  action?: string;
  limit?: number;
  offset?: number;
}): Promise<AuditLogResponse> {
  const { data } = await client.get<AuditLogResponse>('/audit/logs', { params });
  return data;
}
