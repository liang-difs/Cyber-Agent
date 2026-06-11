import axios from 'axios';

export function getScoreColor(score: number): string {
  if (score >= 80) return '#f5222d';
  if (score >= 60) return '#fa8c16';
  if (score >= 40) return '#fadb14';
  return '#52c41a';
}

export function getScoreStatus(score: number): 'exception' | 'active' | 'normal' | 'success' {
  if (score >= 80) return 'exception';
  if (score >= 60) return 'active';
  if (score >= 40) return 'normal';
  return 'success';
}

export function parseNumericScore(raw: string | undefined): number {
  if (!raw) return 0;
  const match = raw.match(/[\d.]+/);
  return match ? parseFloat(match[0]) : 0;
}

export function extractErrorMessage(err: unknown): string {
  if (axios.isAxiosError(err)) {
    return err.response?.data?.detail || err.message || '请求失败';
  }
  if (err instanceof Error) {
    return err.message;
  }
  return '未知错误';
}

export function formatDate(iso: string | undefined): string {
  if (!iso) return '-';
  try {
    return new Date(iso).toLocaleString('zh-CN');
  } catch {
    return iso;
  }
}

export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
