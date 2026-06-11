import { useState } from 'react';
import { Avatar, Typography, message as antMsg } from 'antd';
import {
  UserOutlined, RobotOutlined, LoadingOutlined,
  CopyOutlined, ReloadOutlined, DownOutlined, BulbOutlined,
} from '@ant-design/icons';
import type { ChatMessage as ChatMessageType } from '../../types/api';
import ResponseCards from '../ResponseCards';

const { Text } = Typography;

interface Props {
  message: ChatMessageType;
  isLast?: boolean;
  onRegenerate?: () => void;
}

function summarizeThinking(text: string): string {
  const lower = text.toLowerCase();
  if (lower.includes('pcap') || lower.includes('capture')) return '正在分析网络流量...';
  if (lower.includes('cve') || lower.includes('vulnerability')) return '正在查询漏洞信息...';
  if (lower.includes('cve_catalog') || lower.includes('kev hit rate') || lower.includes('结构化查询')) return '正在整理漏洞统计...';
  if (lower.includes('threat') || lower.includes('ip_threat') || lower.includes('threat_intel')) return '正在查询威胁情报...';
  if (lower.includes('ioc') || lower.includes('indicator')) return '正在分析威胁指标...';
  if (lower.includes('whois') || lower.includes('注册信息')) return '正在查询 WHOIS 信息...';
  if (lower.includes('dns') || lower.includes('dns_lookup')) return '正在查询 DNS 记录...';
  if (lower.includes('ssl') || lower.includes('证书')) return '正在查询 SSL 证书...';
  if (lower.includes('planner') || lower.includes('调查计划')) return '正在生成调查计划...';
  if (lower.includes('rule_match') || lower.includes('sigma') || lower.includes('yara')) return '正在匹配检测规则...';
  if (lower.includes('final_answer') || lower.includes('综合')) return '正在生成分析报告...';
  if (lower.includes('search') || lower.includes('搜索')) return '正在搜索相关信息...';
  return '正在推理分析...';
}

export default function ChatMessage({ message, isLast, onRegenerate }: Props) {
  const isUser = message.role === 'user';
  const [thinkingExpanded, setThinkingExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(message.content);
      setCopied(true);
      antMsg.success('已复制到剪贴板');
      setTimeout(() => setCopied(false), 2000);
    } catch {
      antMsg.error('复制失败');
    }
  };

  return (
    <div
      className={`message-wrapper ${isUser ? 'message-wrapper-user' : 'message-wrapper-assistant'}`}
    >
      {!isUser && <Avatar icon={<RobotOutlined />} style={{ backgroundColor: 'var(--app-primary)' }} />}
      <div className={isUser ? 'message-user-container' : 'message-assistant-container'}>
        {/* Thinking block (collapsed by default) */}
        {!isUser && message.thinking && (
          <div
            className="thinking-block"
            onClick={() => setThinkingExpanded(!thinkingExpanded)}
          >
            <div className="thinking-summary">
              <BulbOutlined />
              <span>{summarizeThinking(message.thinking)}</span>
              <DownOutlined
                style={{
                  fontSize: 10,
                  transform: thinkingExpanded ? 'rotate(180deg)' : 'none',
                  transition: 'transform 0.2s',
                }}
              />
            </div>
            {thinkingExpanded && (
              <div className="thinking-full">{message.thinking}</div>
            )}
          </div>
        )}

        <div style={{ position: 'relative' }}>
          {/* Hover actions for assistant messages */}
          {!isUser && message.content && (
            <div className="message-actions">
              <div className="message-action-btn" onClick={handleCopy} title="复制">
                <CopyOutlined />
              </div>
              {isLast && onRegenerate && (
                <div className="message-action-btn" onClick={onRegenerate} title="重新生成">
                  <ReloadOutlined />
                </div>
              )}
            </div>
          )}

          <div
            className={isUser ? 'message-bubble-user' : 'message-report-block'}
          >
            {isUser ? (
              <span style={{ whiteSpace: 'pre-wrap' }}>{message.content}</span>
            ) : message.content ? (
              <ResponseCards
                content={message.content}
                streaming={message.streaming}
                responseType={message.metadata?.response_type as 'cve' | 'cve_catalog' | 'ioc' | 'ip' | 'markdown' | undefined}
              />
            ) : message.thinking ? (
              <LoadingOutlined style={{ color: 'var(--app-text-tertiary)' }} />
            ) : (
              <LoadingOutlined style={{ color: 'var(--app-text-tertiary)' }} />
            )}
            {/* Error banner (separate from content) */}
            {!isUser && message.metadata?.error != null && (
              <div style={{
                marginTop: 8,
                padding: '6px 10px',
                borderRadius: 6,
                background: 'var(--app-danger-bg, #fff2f0)',
                border: '1px solid var(--app-danger-border, #ffccc7)',
                fontSize: 13,
                color: 'var(--app-danger, #ff4d4f)',
              }}>
                {'⚠️ '}{String(message.metadata.error)}
              </div>
            )}
          </div>
        </div>
      </div>
      {isUser && <Avatar icon={<UserOutlined />} style={{ backgroundColor: 'var(--app-success)' }} />}
    </div>
  );
}
