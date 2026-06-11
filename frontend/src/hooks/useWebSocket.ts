import { useRef, useState, useCallback, useEffect } from 'react';
import type { WSEvent } from '../types/api';

const MAX_EVENTS = 500;

type QueuedWSEvent = WSEvent & { _seq: number };

interface UseWebSocketReturn {
  connected: boolean;
  sendMessage: (content: string, sessionId?: string, attachments?: Array<{ path: string; name: string }>) => boolean;
  sendStop: () => void;
  events: QueuedWSEvent[];
  clearEvents: () => void;
}

function getWsUrl(token: string): string {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${window.location.host}/api/v1/agent/chat?token=${token}`;
}

export function useWebSocket(token: string | null): UseWebSocketReturn {
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState<QueuedWSEvent[]>([]);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>();
  const reconnectCount = useRef(0);
  const eventSeqRef = useRef(0);

  const connect = useCallback(() => {
    if (!token || wsRef.current?.readyState === WebSocket.OPEN) return;

    const ws = new WebSocket(getWsUrl(token));

    ws.onopen = () => {
      setConnected(true);
      reconnectCount.current = 0;
    };
    ws.onclose = () => {
      setConnected(false);
      wsRef.current = null;
      const delay = Math.min(1000 * Math.pow(2, reconnectCount.current), 10000);
      reconnectCount.current++;
      reconnectTimer.current = setTimeout(() => connect(), delay);
    };
    ws.onerror = () => ws.close();
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as WSEvent;
        setEvents((prev) => {
          const next = [...prev, { ...data, _seq: ++eventSeqRef.current }];
          return next.length > MAX_EVENTS ? next.slice(-MAX_EVENTS) : next;
        });
      } catch {
        // ignore parse errors
      }
    };

    wsRef.current = ws;
  }, [token]);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, [connect]);

  const sendMessage = useCallback((content: string, sessionId?: string, attachments?: Array<{ path: string; name: string }>): boolean => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: 'chat', content, session_id: sessionId, attachments: attachments || [] }));
      return true;
    }
    return false;
  }, []);

  const sendStop = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: 'stop' }));
    }
  }, []);

  const clearEvents = useCallback(() => setEvents([]), []);

  return { connected, sendMessage, sendStop, events, clearEvents };
}
