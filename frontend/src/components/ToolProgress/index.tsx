import { useState } from 'react';
import { Tag, Space, Spin, Typography } from 'antd';
import { CheckCircleFilled, CloseCircleFilled, LoadingOutlined, DownOutlined, RightOutlined } from '@ant-design/icons';
import type { ToolExecution } from '../../types/api';

const { Text } = Typography;

interface Props {
  toolCalls: ToolExecution[];
}

const MAX_VISIBLE = 2;
const MAX_ERR_LEN = 80;

const statusConfig: Record<string, { color: string; icon: React.ReactNode }> = {
  running: { color: 'processing', icon: <Spin indicator={<LoadingOutlined spin />} size="small" /> },
  success: { color: 'success', icon: <CheckCircleFilled /> },
  failed: { color: 'error', icon: <CloseCircleFilled /> },
  queued: { color: 'default', icon: <Spin size="small" /> },
  retrying: { color: 'warning', icon: <Spin indicator={<LoadingOutlined spin />} size="small" /> },
  timeout: { color: 'warning', icon: <CloseCircleFilled /> },
  cancelled: { color: 'default', icon: <CloseCircleFilled /> },
};

function CollapsibleError({ text }: { text: string }) {
  const [expanded, setExpanded] = useState(false);
  const needsCollapse = text.length > MAX_ERR_LEN;
  const displayText = needsCollapse && !expanded ? text.slice(0, MAX_ERR_LEN) + '...' : text;

  return (
    <div style={{ fontSize: 12, marginTop: 2 }}>
      <Text type="danger">{displayText}</Text>
      {needsCollapse && (
        <a
          onClick={() => setExpanded(!expanded)}
          style={{ fontSize: 12, marginLeft: 4, cursor: 'pointer', color: 'var(--app-primary)' }}
        >
          {expanded ? <><RightOutlined /> 收起</> : <><DownOutlined /> 展开</>}
        </a>
      )}
    </div>
  );
}

export default function ToolProgress({ toolCalls }: Props) {
  // Filter out internal error entries (parse_failed etc.)
  const visible = toolCalls.filter(tc => tc.tool !== 'error');
  const hiddenCount = visible.length - MAX_VISIBLE;
  const displayed = visible.slice(-MAX_VISIBLE);

  return (
    <div style={{ marginBottom: 8 }}>
      {hiddenCount > 0 && (
        <div style={{ fontSize: 12, color: 'var(--app-text-tertiary)', marginBottom: 4 }}>
          ... 已完成 {hiddenCount} 个工具调用
        </div>
      )}
      <Space direction="vertical" size={4} style={{ width: '100%' }}>
        {displayed.map((tc, i) => {
          const config = statusConfig[tc.status];
          const elapsed = tc.endTime ? ((tc.endTime - tc.startTime) / 1000).toFixed(1) : null;
          const displayName = tc.label || tc.tool;
          return (
            <div
              key={`${tc.tool}-${i}`}
              style={{
                padding: '4px 8px',
                borderRadius: 6,
                background: 'var(--app-surface-elevated)',
                fontSize: 13,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {config.icon}
                <Tag color={config.color}>{displayName}</Tag>
                <span style={{ color: 'var(--app-text-tertiary)' }}>
                  {tc.status === 'running' ? '执行中...' : elapsed ? `${elapsed}s` : ''}
                </span>
              </div>
              {tc.error && tc.status === 'failed' && <CollapsibleError text={tc.error} />}
            </div>
          );
        })}
      </Space>
    </div>
  );
}
