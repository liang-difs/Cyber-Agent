import client from './client';
import type { ChatMessage, Session } from '../types/api';

interface ChatSessionPayload {
  id: string;
  title: string;
  lastMessage: string;
  updatedAt: number;
  messageCount: number;
  summary?: string | null;
  modelName?: string | null;
  userId?: string | null;
  tenantId: string;
}

interface ChatMessagePayload {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: number;
  toolCalls?: Array<Record<string, any>>;
  toolCallId?: string | null;
  thinking?: string | null;
  metadata?: Record<string, any>;
}

export interface ChatSessionExportPayload {
  session: {
    id: string;
    tenant_id: string;
    user_id?: string | null;
    title: string;
    summary?: string | null;
    model_name?: string | null;
    created_at: number;
    updated_at: number;
    last_message_preview?: string | null;
    message_count: number;
    metadata?: Record<string, any> | null;
  };
  messages: Array<{
    id: string;
    role: string;
    content: string;
    timestamp: number;
    tool_calls?: Array<Record<string, any>>;
    tool_call_id?: string | null;
    thinking?: string | null;
    metadata?: Record<string, any>;
  }>;
}

function normalizeSession(payload: ChatSessionPayload): Session {
  return {
    id: payload.id,
    title: payload.title,
    lastMessage: payload.lastMessage,
    updatedAt: payload.updatedAt,
    messageCount: payload.messageCount,
    summary: payload.summary || undefined,
    modelName: payload.modelName || undefined,
    userId: payload.userId || undefined,
    tenantId: payload.tenantId,
  };
}

function normalizeMessage(payload: ChatMessagePayload): ChatMessage {
  return {
    id: payload.id,
    role: payload.role,
    content: payload.content,
    timestamp: payload.timestamp,
    thinking: payload.thinking || undefined,
    toolCalls: payload.toolCalls || [],
    toolCallId: payload.toolCallId || undefined,
    metadata: payload.metadata || {},
  } as ChatMessage;
}

export async function listChatSessions(limit = 50, offset = 0): Promise<Session[]> {
  const response = await client.get<ChatSessionPayload[]>('/agent/sessions', { params: { limit, offset } });
  return response.data.map(normalizeSession);
}

export async function createChatSession(): Promise<Session> {
  const response = await client.post<ChatSessionPayload>('/agent/sessions');
  return normalizeSession(response.data);
}

export async function getChatSessionMessages(sessionId: string): Promise<ChatMessage[]> {
  const response = await client.get<ChatMessagePayload[]>(`/agent/sessions/${sessionId}/messages`);
  return response.data.map(normalizeMessage);
}

export async function deleteChatSession(sessionId: string): Promise<void> {
  await client.delete(`/agent/sessions/${sessionId}`);
}

export async function renameChatSession(sessionId: string, title: string): Promise<Session> {
  const response = await client.patch<ChatSessionPayload>(`/agent/sessions/${sessionId}`, { title });
  return normalizeSession(response.data);
}

export async function exportChatSession(sessionId: string): Promise<ChatSessionExportPayload> {
  const response = await client.get<ChatSessionExportPayload>(`/agent/sessions/${sessionId}/export`);
  return response.data;
}
