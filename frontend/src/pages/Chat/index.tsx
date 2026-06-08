import { useEffect, useState, useRef } from 'react';
import { message as antMsg } from 'antd';
import { useAuthStore } from '../../stores/auth';
import { useChatStore } from '../../stores/chat';
import { useWebSocket } from '../../hooks/useWebSocket';
import { getDetailedHealth } from '../../api/monitor';
import type { HealthCheck } from '../../types/api';
import SessionList from './SessionList';
import MessageList from './MessageList';
import MessageInput from './MessageInput';
import RuntimeStatusBar from './RuntimeStatusBar';
import './chat.css';

const TOOL_LABELS: Record<string, string> = {
  cve_lookup: 'CVE 漏洞查询',
  cve_catalog: 'CVE 批量筛选',
  ioc_lookup: 'IoC 威胁情报',
  ip_threat_analysis: 'IP 威胁分析',
  pcap_analysis: 'PCAP 流量分析',
  rag_search: '知识库检索',
  web_search: '联网搜索',
  nmap_scan: '端口扫描',
  vuln_scan: '漏洞扫描',
  dir_scan: '目录枚举',
  log_analysis: '日志分析',
  hash_lookup: 'Hash 查询',
  encoding_tool: '编解码工具',
  archive: '压缩包分析',
  api_doc_parser: 'API 文档解析',
  config_parser: '配置文件解析',
  binary_analysis: '二进制分析',
  task_planner: '任务规划',
  rule_match: '规则匹配',
  knowledge_graph: '知识图谱',
  response_action: '响应动作',
  echo: '回显测试',
};

export default function Chat() {
  const token = useAuthStore((s) => s.token);
  const { connected, sendMessage, sendStop, events, clearEvents } = useWebSocket(token);
  const {
    currentSessionId, addMessage, createSession, processEvents,
    stopGeneration, clearInterrupted, autoTitleSession, hydrateSessions,
  } = useChatStore();

  // Derive per-session state from store
  const sessionData = useChatStore((s) => currentSessionId ? s.sessionData[currentSessionId] : undefined);
  const usage = sessionData?.usage || { promptTokens: 0, completionTokens: 0, reasoningTokens: 0, toolTokens: 0, totalTokens: 0, turnCount: 0 };
  const streamingState = sessionData?.streamingState || 'idle';
  const interrupted = sessionData?.interrupted || false;
  const modelName = sessionData?.modelName || '';
  const contextLimit = sessionData?.contextLimit || 64000;
  const toolExecutions = sessionData?.toolExecutions || [];

  const [isWaiting, setIsWaiting] = useState(false);
  const [llmHealth, setLlmHealth] = useState<HealthCheck | undefined>();
  const processedSeqRef = useRef(0);

  useEffect(() => {
    if (!token) return;
    void hydrateSessions();
  }, [token, hydrateSessions]);

  useEffect(() => {
    const newEvents = events.filter((event) => event._seq > processedSeqRef.current);
    if (newEvents.length === 0) return;

    processedSeqRef.current = newEvents[newEvents.length - 1]._seq;

    processEvents(newEvents as any, TOOL_LABELS);

    for (const e of newEvents) {
      if ((e as any).type === 'done') {
        setIsWaiting(false);
        autoTitleSession();
        break;
      }
    }
  }, [events]);

  useEffect(() => {
    let cancelled = false;
    const fetchLlmHealth = async () => {
      try {
        const health = await getDetailedHealth();
        if (!cancelled) setLlmHealth(health.checks?.llm);
      } catch {
        if (!cancelled) setLlmHealth(undefined);
      }
    };
    fetchLlmHealth();
    const timer = window.setInterval(fetchLlmHealth, 30000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const handleClearEvents = () => {
    processedSeqRef.current = 0;
    clearEvents();
  };

  const handleSend = async (content: string, attachments?: Array<{ path: string; name: string }>) => {
    let sid = currentSessionId;
    try {
      if (!sid) {
        sid = await createSession();
      }
    } catch {
      antMsg.error('会话创建失败，请稍后重试');
      return;
    }

    // Clear interrupted state on new message
    if (interrupted) {
      clearInterrupted();
    }

    addMessage({
      id: `user-${Date.now()}`,
      role: 'user',
      content,
      timestamp: Date.now(),
    }, sid);

    addMessage({
      id: `assistant-${Date.now()}`,
      role: 'assistant',
      content: '',
      timestamp: Date.now(),
    }, sid);

    handleClearEvents();
    setIsWaiting(true);

    const sent = sendMessage(content, sid, attachments);
    if (!sent) {
      antMsg.error('消息发送失败，服务器未连接');
      setIsWaiting(false);
    }
  };

  const handleStop = () => {
    stopGeneration();
    sendStop();
    setIsWaiting(false);
  };

  const handleContinue = () => {
    clearInterrupted();
    handleSend('请继续');
  };

  return (
    <div className="chat-page">
      <div className="chat-shell">
        <SessionList />
        <div className="chat-main">
          <RuntimeStatusBar
            connected={connected}
            modelName={modelName}
            usage={usage}
            contextLimit={contextLimit}
            streamingState={streamingState}
            toolExecutions={toolExecutions}
            llmHealth={llmHealth}
          />
          <MessageList />
          <MessageInput
            onSend={handleSend}
            waiting={isWaiting}
            connected={connected}
            onStop={handleStop}
            interrupted={interrupted}
            onContinue={handleContinue}
          />
        </div>
      </div>
    </div>
  );
}
