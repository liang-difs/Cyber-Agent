import client from './client';
import type { TaskStatus, PcapUploadResponse, AlertTriageResult } from '../types/api';

export async function getTaskStatus(taskId: string): Promise<TaskStatus> {
  const { data } = await client.get<TaskStatus>(`/tasks/${taskId}`);
  return data;
}

export async function uploadPcap(file: File, maxPackets = 10000): Promise<PcapUploadResponse> {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('max_packets', String(maxPackets));
  const { data } = await client.post<PcapUploadResponse>('/tasks/pcap-upload', formData, {
    headers: { 'Content-Type': undefined },
  });
  return data;
}

export async function submitAlertTriage(params: {
  alert_id: string;
  rule_id: string;
  description?: string;
  src_ip?: string;
}): Promise<AlertTriageResult> {
  const { data } = await client.post<AlertTriageResult>('/tasks/alert-triage', null, { params });
  return data;
}

export async function submitPcapAnalysis(params: {
  pcap_path: string;
  max_packets?: number;
}): Promise<{ task_id: string; status: string; queue: string }> {
  const { data } = await client.post('/tasks/pcap-analysis', null, { params });
  return data;
}

export async function uploadFile(file: File): Promise<{
  file_path: string;
  filename: string;
  size_bytes: number;
}> {
  const formData = new FormData();
  formData.append('file', file);
  const { data } = await client.post('/tasks/upload-file', formData, {
    headers: { 'Content-Type': undefined },
  });
  return data;
}

export interface PcapFileInfo {
  filename: string;
  size_bytes: number;
  created_at: string;
}

export async function listPcapFiles(): Promise<{ files: PcapFileInfo[]; total_size_bytes: number }> {
  const { data } = await client.get('/tasks/pcap-files');
  return data;
}
