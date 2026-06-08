import { useState } from 'react';
import {
  CheckCircleFilled, CloseCircleFilled, LoadingOutlined,
  ClockCircleOutlined, SyncOutlined, ExclamationCircleFilled,
  StopFilled, DownOutlined, RightOutlined,
} from '@ant-design/icons';
import { Tag } from 'antd';
import type { ToolExecution, ToolStatus } from '../../types/api';
import './index.css';

const STATUS_ICON: Record<ToolStatus, React.ReactNode> = {
  queued: <ClockCircleOutlined style={{ color: '#999' }} />,
  running: <LoadingOutlined spin style={{ color: '#1677ff' }} />,
  retrying: <SyncOutlined spin style={{ color: '#fa8c16' }} />,
  success: <CheckCircleFilled style={{ color: '#52c41a' }} />,
  timeout: <ExclamationCircleFilled style={{ color: '#faad14' }} />,
  failed: <CloseCircleFilled style={{ color: '#ff4d4f' }} />,
  cancelled: <StopFilled style={{ color: '#999' }} />,
};

const STATUS_TAG: Record<ToolStatus, { color: string; label: string }> = {
  queued: { color: 'default', label: '排队中' },
  running: { color: 'processing', label: '执行中' },
  retrying: { color: 'warning', label: '重试中' },
  success: { color: 'success', label: '完成' },
  timeout: { color: 'warning', label: '超时' },
  failed: { color: 'error', label: '失败' },
  cancelled: { color: 'default', label: '已取消' },
};

function formatDuration(te: ToolExecution): string {
  const end = te.endTime || Date.now();
  const ms = end - te.startTime;
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

interface ToolTimelineProps {
  executions: ToolExecution[];
  maxVisible?: number;
}

export default function ToolTimeline({ executions, maxVisible = 3 }: ToolTimelineProps) {
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [showAll, setShowAll] = useState(false);
  const [collapsed, setCollapsed] = useState(false);

  if (executions.length === 0) return null;

  const visible = showAll ? executions : executions.slice(-maxVisible);
  const hiddenCount = executions.length - visible.length;
  const runningCount = executions.filter(t => t.status === 'running').length;

  const toggleExpand = (id: string) => {
    setExpandedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const renderItems = () => {
    if (collapsed) return null;
    return (
      <div className="tool-timeline-body">
        {hiddenCount > 0 && !showAll && (
          <div className="tool-timeline-show-more" onClick={() => setShowAll(true)}>
            还有 {hiddenCount} 个工具调用，点击展开
          </div>
        )}
        <div className="tool-timeline-items">
          {visible.map((te, i) => {
            const isLast = i === visible.length - 1;
            const isExpanded = expandedIds.has(te.id);
            const hasEvidence = te.evidence && te.evidence.length > 0;
            const hasRagSummary = !!te.ragSummary;
            const tag = STATUS_TAG[te.status];

            return (
              <div key={te.id} className={'tool-timeline-item ' + te.status}>
                <div className="tool-timeline-connector">
                  <span className="tool-timeline-dot">{STATUS_ICON[te.status]}</span>
                  {!isLast && <span className="tool-timeline-line" />}
                </div>
                <div className="tool-timeline-content">
                  <div
                    className="tool-timeline-row"
                    onClick={() => hasEvidence && toggleExpand(te.id)}
                    style={{ cursor: hasEvidence ? 'pointer' : 'default' }}
                  >
                    <span className="tool-timeline-label">{te.label || te.tool}</span>
                    <Tag color={tag.color} style={{ marginLeft: 8 }}>{tag.label}</Tag>
                    <span className="tool-timeline-duration">{formatDuration(te)}</span>
                    {(hasEvidence || hasRagSummary) && (
                      <span className="tool-timeline-expand-icon">
                        {isExpanded ? <DownOutlined /> : <RightOutlined />}
                      </span>
                    )}
                  </div>
                  {te.error && te.status === 'failed' && (
                    <div className="tool-timeline-error">{te.error}</div>
                  )}
                  {isExpanded && hasEvidence && (
                    <div className="tool-timeline-evidence">
                      <div className="evidence-header">证据来源</div>
                      {te.evidence!.map((ev, j) => (
                        <div key={j} className="evidence-item">
                          <span className="evidence-source">{ev.source}</span>
                          {ev.label && <span className="evidence-label">{ev.label}</span>}
                          {ev.confidence != null && (
                            <span className="evidence-confidence">
                              {Math.round(ev.confidence * 100)}%
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                  {isExpanded && hasRagSummary && (
                    <div className="tool-timeline-evidence">
                      <div className="evidence-header">RAG 检索详情</div>
                      <div className="evidence-item">
                        <span className="evidence-source">查询: {te.ragSummary!.query}</span>
                      </div>
                      <div className="evidence-item">
                        <span className="evidence-source">
                          命中: {te.ragSummary!.found ? `${te.ragSummary!.resultCount} 条结果` : '未命中'}
                        </span>
                      </div>
                      {te.ragSummary!.sources.length > 0 && (
                        <div className="evidence-item">
                          <span className="evidence-source">
                            来源: {te.ragSummary!.sources.join(', ')}
                          </span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  return (
    <div className="tool-timeline">
      <div
        className="tool-timeline-header"
        onClick={() => setCollapsed(!collapsed)}
        style={{ cursor: 'pointer', userSelect: 'none' }}
      >
        <span className="tool-timeline-icon">🔧</span>
        <span className="tool-timeline-title">
          工具调用 ({executions.length})
        </span>
        {runningCount > 0 && (
          <Tag color="processing" style={{ marginLeft: 8 }}>
            {runningCount} 运行中
          </Tag>
        )}
        <span style={{ marginLeft: 'auto', fontSize: 10, color: '#999' }}>
          {collapsed ? <DownOutlined /> : <RightOutlined />}
        </span>
      </div>
      {renderItems()}
    </div>
  );
}
