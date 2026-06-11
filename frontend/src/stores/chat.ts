import { create } from 'zustand';
import {
  createChatSession,
  deleteChatSession,
  getChatSessionMessages,
  listChatSessions,
  renameChatSession,
} from '../api/chat';
import type {
  ChatMessage, Session, ToolExecution, ToolStatus,
  UsageMetrics, StreamingState, EvidenceItem, WSEvent,
} from '../types/api';

const CURRENT_SESSION_KEY = 'cybersec.chat.currentSessionId';

interface WSEventInput {
  type: string;
  tool?: string;
  tool_call_id?: string;
  content?: string;
  success?: boolean;
  session_id?: string;
  total_tokens?: number;
  message?: string;
  code?: string;
  evidence?: EvidenceItem[];
  evidence_source?: string[];
  execution_time_ms?: number;
  error?: string;
  provider?: string;
  model?: string;
  rag_summary?: { query: string; found: boolean; result_count: number; sources: string[] };
}

interface SessionData {
  messages: ChatMessage[];
  toolExecutions: ToolExecution[];
  usage: UsageMetrics;
  streamingState: StreamingState;
  interrupted: boolean;
  modelName: string;
  contextLimit: number;
}

interface ChatState {
  sessions: Session[];
  currentSessionId: string | null;
  sessionData: Record<string, SessionData>;
  messages: ChatMessage[];

  // AbortController for stop generation
  abortController: AbortController | null;
  setAbortController: (controller: AbortController | null) => void;

  // Session management
  setCurrentSession: (id: string) => void;
  hydrateSessions: () => Promise<void>;
  loadSessionMessages: (sessionId: string) => Promise<void>;
  selectSession: (sessionId: string) => Promise<void>;
  createSession: () => Promise<string>;
  updateSessionId: (backendId: string) => void;
  renameSession: (sessionId: string, title: string) => Promise<Session | null>;
  deleteSession: (sessionId: string) => Promise<boolean>;

  // Messages
  addMessage: (msg: ChatMessage, sessionId?: string) => void;
  setMessages: (messages: ChatMessage[]) => void;

  // Tool executions (independent from messages)
  getToolExecutions: () => ToolExecution[];

  // Process WS events
  processEvents: (events: WSEventInput[], toolLabels: Record<string, string>) => string | null;

  // Stop generation
  stopGeneration: () => void;

  // Continue after interrupt
  clearInterrupted: () => void;

  // Auto-title
  autoTitleSession: () => void;
}

const DEFAULT_USAGE: UsageMetrics = {
  promptTokens: 0,
  completionTokens: 0,
  reasoningTokens: 0,
  toolTokens: 0,
  totalTokens: 0,
  turnCount: 0,
};

const DEFAULT_SESSION_DATA: SessionData = {
  messages: [],
  toolExecutions: [],
  usage: { ...DEFAULT_USAGE },
  streamingState: 'idle',
  interrupted: false,
  modelName: '',
  contextLimit: 64000,
};

function getOrCreateSessionData(data: Record<string, SessionData>, sid: string): SessionData {
  if (!data[sid]) {
    data[sid] = { ...DEFAULT_SESSION_DATA, usage: { ...DEFAULT_USAGE } };
  }
  return data[sid];
}

function persistCurrentSessionId(sessionId: string | null) {
  if (typeof window === 'undefined') return;
  if (sessionId) {
    window.localStorage.setItem(CURRENT_SESSION_KEY, sessionId);
  } else {
    window.localStorage.removeItem(CURRENT_SESSION_KEY);
  }
}

function readCurrentSessionId() {
  if (typeof window === 'undefined') return null;
  return window.localStorage.getItem(CURRENT_SESSION_KEY);
}

function previewMessage(content: string) {
  const text = content.trim().replace(/\s+/g, ' ');
  return text.length > 80 ? `${text.slice(0, 80)}...` : text;
}

export const useChatStore = create<ChatState>((set, get) => ({
  sessions: [],
  currentSessionId: null,
  sessionData: {},
  messages: [],
  abortController: null,

  setAbortController: (controller) => set({ abortController: controller }),

  setCurrentSession: (id) => {
    persistCurrentSessionId(id);
    set((state) => {
      const sd = state.sessionData[id];
      return {
        currentSessionId: id,
        messages: sd?.messages || [],
      };
    });
  },

  hydrateSessions: async () => {
    try {
      const sessions = await listChatSessions();
      const storedSessionId = readCurrentSessionId();
      const nextSessionData: Record<string, SessionData> = {};
      const existingSessionData = get().sessionData;

      for (const session of sessions) {
        nextSessionData[session.id] = existingSessionData[session.id] || {
          ...DEFAULT_SESSION_DATA,
          usage: { ...DEFAULT_USAGE },
        };
      }

      set((state) => ({
        sessions,
        sessionData: {
          ...state.sessionData,
          ...nextSessionData,
        },
      }));

      const selectedId = storedSessionId && sessions.some((session) => session.id === storedSessionId)
        ? storedSessionId
        : sessions[0]?.id || null;

      if (selectedId) {
        await get().selectSession(selectedId);
      } else {
        persistCurrentSessionId(null);
        set({ currentSessionId: null, messages: [] });
      }
    } catch (error) {
      console.error('Failed to hydrate chat sessions:', error);
    }
  },

  loadSessionMessages: async (sessionId) => {
    try {
      const messages = await getChatSessionMessages(sessionId);
      set((state) => {
        const nextSessionData = { ...state.sessionData };
        const sd = { ...getOrCreateSessionData(nextSessionData, sessionId) };
        sd.messages = messages;
        nextSessionData[sessionId] = sd;
        return {
          sessionData: nextSessionData,
          messages: state.currentSessionId === sessionId ? messages : state.messages,
        };
      });
    } catch (error) {
      console.error(`Failed to load chat session ${sessionId}:`, error);
    }
  },

  selectSession: async (sessionId) => {
    persistCurrentSessionId(sessionId);
    set((state) => {
      const sd = state.sessionData[sessionId];
      return {
        currentSessionId: sessionId,
        messages: sd?.messages || [],
      };
    });

    const cached = get().sessionData[sessionId];
    if (!cached || cached.messages.length === 0) {
      await get().loadSessionMessages(sessionId);
    }
  },

  createSession: async () => {
    const session = await createChatSession();
    persistCurrentSessionId(session.id);
    set((state) => {
      const nextSessionData = { ...state.sessionData };
      nextSessionData[session.id] = { ...DEFAULT_SESSION_DATA, usage: { ...DEFAULT_USAGE } };
      return {
        sessions: [session, ...state.sessions.filter((item) => item.id !== session.id)],
        currentSessionId: session.id,
        sessionData: nextSessionData,
        messages: [],
      };
    });
    return session.id;
  },

  renameSession: async (sessionId, title) => {
    const updated = await renameChatSession(sessionId, title);
    set((state) => {
      const nextSessions = state.sessions.map((session) =>
        session.id === sessionId ? { ...session, ...updated } : session,
      );
      const nextSessionData = { ...state.sessionData };
      const sd = nextSessionData[sessionId];
      if (sd) {
        nextSessionData[sessionId] = { ...sd };
      }
      return {
        sessions: nextSessions,
        sessionData: nextSessionData,
      };
    });
    return updated;
  },

  deleteSession: async (sessionId) => {
    await deleteChatSession(sessionId);
    set((state) => {
      const nextSessions = state.sessions.filter((session) => session.id !== sessionId);
      const nextSessionData = { ...state.sessionData };
      delete nextSessionData[sessionId];
      const isCurrent = state.currentSessionId === sessionId;
      if (isCurrent) {
        persistCurrentSessionId(null);
      }
      return {
        sessions: nextSessions,
        sessionData: nextSessionData,
        currentSessionId: isCurrent ? nextSessions[0]?.id || null : state.currentSessionId,
        messages: isCurrent ? (nextSessionData[nextSessions[0]?.id || '']?.messages || []) : state.messages,
      };
    });
    return true;
  },

  updateSessionId: (backendId) => {
    set((state) => {
      const oldId = state.currentSessionId;
      if (!oldId || oldId === backendId) return state;
      const sd = state.sessionData[oldId];
      if (!sd) {
        persistCurrentSessionId(backendId);
        return { currentSessionId: backendId };
      }
      const newSessionData = { ...state.sessionData };
      delete newSessionData[oldId];
      newSessionData[backendId] = sd;
      const sessions = state.sessions.map((s) =>
        s.id === oldId ? { ...s, id: backendId } : s,
      );
      persistCurrentSessionId(backendId);
      return {
        currentSessionId: backendId,
        sessionData: newSessionData,
        messages: sd.messages || [],
        sessions,
      };
    });
  },

  addMessage: (msg, explicitSessionId) => {
    set((state) => {
      const sid = explicitSessionId || state.currentSessionId;
      if (!sid) return state;
      const nextSessionData = { ...state.sessionData };
      const sd = { ...getOrCreateSessionData(nextSessionData, sid) };
      sd.messages = [...sd.messages, msg];
      nextSessionData[sid] = sd;
      const nextSessions = state.sessions.map((session) => {
        if (session.id !== sid) return session;
        const nextSession = { ...session };
        if (msg.content.trim()) {
          nextSession.lastMessage = previewMessage(msg.content);
          nextSession.updatedAt = msg.timestamp || Date.now();
          nextSession.messageCount = (session.messageCount || 0) + 1;
        }
        return nextSession;
      });
      return { sessionData: nextSessionData, messages: sd.messages, sessions: nextSessions };
    });
  },

  setMessages: (messages) => {
    set((state) => {
      const sid = state.currentSessionId;
      if (!sid) return { messages };
      const newSessionData = { ...state.sessionData };
      const sd = { ...getOrCreateSessionData(newSessionData, sid) };
      sd.messages = messages;
      newSessionData[sid] = sd;
      return {
        sessionData: newSessionData,
        messages,
        sessions: state.sessions.map((session) => (
          session.id === sid
            ? {
                ...session,
                lastMessage: messages[messages.length - 1]?.content
                  ? previewMessage(messages[messages.length - 1].content)
                  : session.lastMessage,
                updatedAt: messages[messages.length - 1]?.timestamp || session.updatedAt,
                messageCount: messages.length,
              }
            : session
        )),
      };
    });
  },

  getToolExecutions: () => {
    const { currentSessionId, sessionData } = get();
    if (!currentSessionId) return [];
    return sessionData[currentSessionId]?.toolExecutions ?? [];
  },

  stopGeneration: () => {
    const { abortController, currentSessionId, sessionData } = get();
    abortController?.abort();
    set((state) => {
      const sid = state.currentSessionId;
      if (!sid) return { abortController: null };
      const newSessionData = { ...state.sessionData };
      const sd = { ...getOrCreateSessionData(newSessionData, sid) };
      sd.streamingState = 'idle';
      sd.interrupted = true;
      // Mark all running tools as cancelled
      sd.toolExecutions = sd.toolExecutions.map(te =>
        te.status === 'running' || te.status === 'queued'
          ? { ...te, status: 'cancelled' as ToolStatus, endTime: Date.now() }
          : te,
      );
      newSessionData[sid] = sd;
      return { abortController: null, sessionData: newSessionData };
    });
  },

  clearInterrupted: () => {
    set((state) => {
      const sid = state.currentSessionId;
      if (!sid) return state;
      const newSessionData = { ...state.sessionData };
      const sd = { ...getOrCreateSessionData(newSessionData, sid) };
      sd.interrupted = false;
      newSessionData[sid] = sd;
      return { sessionData: newSessionData };
    });
  },

  autoTitleSession: () => {
    set((state) => {
      const sid = state.currentSessionId;
      if (!sid) return state;
      const session = state.sessions.find(s => s.id === sid);
      if (!session || session.title !== '新会话') return state;
      const sd = state.sessionData[sid];
      if (!sd) return state;
      const firstUser = sd.messages.find(m => m.role === 'user');
      if (!firstUser) return state;
      const title = firstUser.content.slice(0, 20).replace(/\n/g, ' ')
        + (firstUser.content.length > 20 ? '...' : '');
      return {
        sessions: state.sessions.map(s => s.id === sid ? { ...s, title } : s),
      };
    });
  },

  processEvents: (events, toolLabels) => {
    let backendSessionId: string | null = null;
    set((state) => {
      const sid = state.currentSessionId;
      if (!sid) return state;
      const newSessionData = { ...state.sessionData };
      const sd = { ...getOrCreateSessionData(newSessionData, sid) };
      const msgs = [...sd.messages];
      let last = msgs[msgs.length - 1];
      const toolExecs = [...sd.toolExecutions];
      let streamingState = sd.streamingState;

      for (const event of events) {
        switch (event.type) {
          case 'llm_backend':
            sd.modelName = event.model || '';
            break;

          case 'thinking':
            if (last && last.role === 'assistant') {
              msgs[msgs.length - 1] = {
                ...last,
                thinking: (last.thinking || '') + (event.content || ''),
              };
              last = msgs[msgs.length - 1];
            }
            streamingState = 'thinking';
            break;

          case 'tool_call': {
            const tcId = event.tool_call_id || `tc_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
            const assistantMessageId = last?.role === 'assistant' ? last.id : undefined;
            const te: ToolExecution = {
              id: tcId,
              tool: event.tool || '',
              label: toolLabels[event.tool || ''] || event.tool || '',
              status: 'running',
              startTime: Date.now(),
              messageId: assistantMessageId,
            };
            toolExecs.push(te);
            streamingState = 'tool_calling';
            break;
          }

          case 'tool_result': {
            const tcId = event.tool_call_id;
            let idx = -1;
            if (tcId) {
              idx = toolExecs.findIndex((t: ToolExecution) => t.id === tcId);
            } else {
              for (let j = toolExecs.length - 1; j >= 0; j--) {
                if (toolExecs[j].tool === event.tool && toolExecs[j].status === 'running') {
                  idx = j;
                  break;
                }
              }
            }
            if (idx >= 0) {
              // Use backend execution_time_ms for accurate duration, fallback to Date.now()
              const execMs = event.execution_time_ms;
              const endTime = execMs && execMs > 0
                ? toolExecs[idx].startTime + execMs
                : Date.now();
              // Convert evidence_source strings to EvidenceItem[] if no evidence provided
              const evidence = event.evidence || (
                event.evidence_source && event.evidence_source.length > 0
                  ? event.evidence_source.map((src: string) => ({ source: src }))
                  : toolExecs[idx].evidence
              );
              toolExecs[idx] = {
                ...toolExecs[idx],
                status: event.success ? 'success' : 'failed',
                endTime,
                evidence,
                error: event.error || toolExecs[idx].error,
                ...(event.rag_summary ? {
                  ragSummary: {
                    query: event.rag_summary.query,
                    found: event.rag_summary.found,
                    resultCount: event.rag_summary.result_count,
                    sources: event.rag_summary.sources,
                  },
                } : {}),
              };
            }
            break;
          }

          case 'token':
            if (last && last.role === 'assistant') {
              msgs[msgs.length - 1] = {
                ...last,
                content: last.content + (event.content || ''),
                streaming: true,
              };
              last = msgs[msgs.length - 1];
            }
            streamingState = 'answering';
            break;

          case 'done':
            if (event.session_id) {
              backendSessionId = event.session_id;
            }
            if (last && last.role === 'assistant') {
              msgs[msgs.length - 1] = { ...last, streaming: false };
              last = msgs[msgs.length - 1];
            }
            sd.usage.totalTokens = event.total_tokens ?? sd.usage.totalTokens;
            sd.usage.turnCount += 1;
            streamingState = 'idle';
            break;

          case 'usage':
            sd.usage.totalTokens = event.total_tokens ?? sd.usage.totalTokens;
            break;

          case 'error':
            if (event.message && !event.message.includes('parse_failed') && last && last.role === 'assistant') {
              // Store error separately from content to avoid polluting message text
              msgs[msgs.length - 1] = {
                ...last,
                metadata: { ...last.metadata, error: event.message },
              };
              last = msgs[msgs.length - 1];
            }
            break;
        }
      }

      sd.messages = msgs;
      sd.toolExecutions = toolExecs;
      sd.streamingState = streamingState;
      newSessionData[sid] = sd;
      const lastAssistant = [...msgs].reverse().find((msg) => msg.role === 'assistant' && msg.content.trim());
      const nextSessions = state.sessions.map((session) => (
        session.id === sid
          ? {
              ...session,
              lastMessage: lastAssistant ? previewMessage(lastAssistant.content) : session.lastMessage,
              updatedAt: Date.now(),
              messageCount: msgs.length,
            }
          : session
      ));

      return {
        sessionData: newSessionData,
        messages: msgs,
        sessions: nextSessions,
      };
    });
    return backendSessionId;
  },
}));
