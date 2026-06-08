import client from './client';
import type { Alert } from '../types/api';

export interface AlertListResponse {
  alerts: Alert[];
  total: number;
  limit: number;
  offset: number;
}

export async function listAlerts(params?: {
  severity?: string;
  status?: string;
  src_ip?: string;
  limit?: number;
  offset?: number;
}): Promise<AlertListResponse> {
  const { data } = await client.get<AlertListResponse>('/alerts', { params });
  return data;
}

export async function reviewAlert(
  alertId: string,
  body: { status: string; verdict?: string },
): Promise<Alert> {
  const { data } = await client.patch<Alert>(`/alerts/${alertId}`, body);
  return data;
}

export async function analyzeAlert(
  alertId: string,
  taskType: string = 'incident_response',
): Promise<{ success: boolean; task_id: string; alert_id: string; result: any }> {
  const { data } = await client.post(`/alerts/${alertId}/analyze`, { task_type: taskType });
  return data;
}
