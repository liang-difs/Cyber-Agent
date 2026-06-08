import { useCallback, useRef, useState } from 'react';
import { getTaskStatus } from '../api/task';
import type { TaskStatus } from '../types/api';

interface PollOptions {
  intervalMs?: number;
  maxAttempts?: number;
  onStatus?: (status: TaskStatus, attempt: number) => void;
}

function isSuccess(status: string): boolean {
  return status === 'SUCCESS' || status === 'SUCCEEDED';
}

function isFailure(status: string): boolean {
  return status === 'FAILURE' || status === 'FAILED';
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function useTaskPolling() {
  const [polling, setPolling] = useState(false);
  const cancelledRef = useRef(false);

  const cancel = useCallback(() => {
    cancelledRef.current = true;
    setPolling(false);
  }, []);

  const pollTask = useCallback(async (taskId: string, options: PollOptions = {}): Promise<TaskStatus> => {
    const intervalMs = options.intervalMs ?? 2000;
    const maxAttempts = options.maxAttempts ?? 120;
    cancelledRef.current = false;
    setPolling(true);

    try {
      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        if (cancelledRef.current) {
          throw new Error('轮询已取消');
        }

        const status = await getTaskStatus(taskId);
        options.onStatus?.(status, attempt);

        if (isSuccess(status.status) || isFailure(status.status) || status.warning) {
          return status;
        }

        await delay(intervalMs);
      }
      throw new Error('轮询超时');
    } finally {
      setPolling(false);
    }
  }, []);

  return { polling, pollTask, cancel };
}
