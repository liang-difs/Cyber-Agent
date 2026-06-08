import { Tag, Tooltip, Progress } from 'antd';
import {
  LoadingOutlined,
} from '@ant-design/icons';
import type { StreamingState, UsageMetrics, ToolExecution } from '../../types/api';
import type { HealthCheck } from '../../types/api';
import LLMModelSwitcher from '../../components/LLMModelSwitcher';
import { useAuthStore } from '../../stores/auth';

interface Props {
  connected: boolean;
  modelName: string;
  usage: UsageMetrics;
  contextLimit: number;
  streamingState: StreamingState;
  toolExecutions: ToolExecution[];
  llmHealth?: HealthCheck;
}

const STREAMING_LABELS: Record<StreamingState, string> = {
  idle: '',
  thinking: '推理中...',
  tool_calling: '工具调用中...',
  answering: '生成中...',
};

export default function RuntimeStatusBar({
  connected, modelName, usage, contextLimit, streamingState, toolExecutions, llmHealth,
}: Props) {
  const user = useAuthStore((s) => s.user);
  const runningTools = toolExecutions.filter(t => t.status === 'running' || t.status === 'retrying');
  const openCircuits = Object.entries(llmHealth?.circuits || {}).filter(([, c]) => c.open);
  const activeModel = modelName || llmHealth?.default_model || '';
  const contextPercent = contextLimit > 0
    ? Math.round((usage.totalTokens / contextLimit) * 100)
    : 0;

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: 16,
      padding: '6px 16px',
      borderBottom: '1px solid var(--app-border)',
      background: 'var(--app-surface-elevated)',
      fontSize: 12,
      color: 'var(--app-text-secondary)',
      flexWrap: 'wrap',
      }}>
      {/* Connection */}
      <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        <span style={{
          width: 6, height: 6, borderRadius: '50%',
          background: connected ? '#52c41a' : '#ff4d4f',
          display: 'inline-block',
        }} />
        {connected ? 'Connected' : 'Disconnected'}
      </span>

      {/* Model with switcher */}
      {activeModel && (
        <LLMModelSwitcher variant="inline" editable={user?.role === 'admin'} />
      )}

      {llmHealth && (
        <Tooltip
          title={
            openCircuits.length > 0
              ? openCircuits.map(([m, c]) => `${m}: reset in ${c.reset_in_seconds}s`).join(' | ')
              : `Fallbacks: ${(llmHealth.fallback_models || []).join(', ') || 'none'}`
          }
        >
          <Tag color={openCircuits.length > 0 ? 'warning' : 'success'} style={{ margin: 0, fontSize: 11 }}>
            LLM {openCircuits.length > 0 ? 'Degraded' : 'Ready'}
          </Tag>
        </Tooltip>
      )}

      {/* Context usage */}
      {usage.totalTokens > 0 && (
        <Tooltip title={`Prompt: ${usage.promptTokens} | Completion: ${usage.completionTokens} | Reasoning: ${usage.reasoningTokens} | Tool: ${usage.toolTokens}`}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span>Context:</span>
            <Progress
              percent={contextPercent}
              size="small"
              style={{ width: 80, margin: 0 }}
              showInfo={false}
              strokeColor={contextPercent > 80 ? '#ff4d4f' : contextPercent > 60 ? '#faad14' : '#1677ff'}
            />
            <span>{(usage.totalTokens / 1000).toFixed(1)}k / {(contextLimit / 1000).toFixed(0)}k</span>
          </span>
        </Tooltip>
      )}

      {/* Streaming state */}
      {streamingState !== 'idle' && (
        <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#1677ff' }}>
          <LoadingOutlined spin style={{ fontSize: 12 }} />
          {STREAMING_LABELS[streamingState]}
        </span>
      )}

      {/* Active tools */}
      {runningTools.length > 0 && (
        <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <LoadingOutlined spin style={{ fontSize: 12, color: '#1677ff' }} />
          {runningTools.length} Tool{runningTools.length > 1 ? 's' : ''} Running
        </span>
      )}

      {/* Turn count */}
      {usage.turnCount > 0 && (
        <span style={{ marginLeft: 'auto', color: 'var(--app-text-tertiary)' }}>
          Turns: {usage.turnCount} | Tokens: {(usage.totalTokens / 1000).toFixed(1)}k
        </span>
      )}
    </div>
  );
}
