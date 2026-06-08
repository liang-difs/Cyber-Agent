import { useEffect, useRef } from 'react';
import { Empty } from 'antd';
import ChatMessage from '../../components/ChatMessage';
import ToolTimeline from '../../components/ToolTimeline';
import { useChatStore } from '../../stores/chat';
import type { ChatMessage as ChatMessageType } from '../../types/api';

export default function MessageList() {
  const messages = useChatStore((s) => s.messages);
  const getToolExecutions = useChatStore((s) => s.getToolExecutions);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  if (messages.length === 0) {
    return (
      <div style={{ flex: 1, display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
        <Empty description="发送消息开始对话" />
      </div>
    );
  }

  const toolExecutions = getToolExecutions();

  return (
    <div className="chat-message-list">
      {messages.map((msg, i) => {
        const isLast = i === messages.length - 1 && msg.role === 'assistant';
        const messageTools = toolExecutions.filter(t => t.messageId === msg.id);
        return (
          <div key={msg.id}>
            <ChatMessage
              message={msg}
              isLast={isLast}
            />
            {messageTools.length > 0 && (
              <div className="message-wrapper message-wrapper-assistant">
                <div className="message-avatar-spacer" />
                <div className="message-assistant-container chat-turn-tools">
                  <ToolTimeline executions={messageTools} />
                </div>
              </div>
            )}
          </div>
        );
      })}

      <div ref={bottomRef} />
    </div>
  );
}
