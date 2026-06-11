# ReAct Agent 优化实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use compose:subagent or compose:execute to implement this plan task-by-task.

**Goal:** 消除代码重复、添加工具缓存和重试机制

**Architecture:** 提取公共逻辑 → 添加缓存层 → 添加重试机制

**Tech Stack:** Python 3.12 + FastAPI

---

## Task 1: 提取公共逻辑，消除重复代码

**Covers:** F1 代码重构

**Files:**
- Create: `backend/app/agent/loop_state.py`
- Modify: `backend/app/agent/react.py`

### 问题分析

`run` 和 `run_streaming` 方法有约 200 行重复逻辑：
- 去重检测 (dedup)
- 工具调用限制
- Web search fallback
- CVE catalog fallback
- 错误处理

### 解决方案

创建 `LoopState` 类封装循环状态和公共逻辑：

```python
# backend/app/agent/loop_state.py
"""Shared state and helpers for ReAct loop."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from app.agent.json_parser import parse_llm_json


@dataclass
class LoopState:
    """Encapsulates mutable state for a single ReAct loop execution."""
    
    # Counters
    tool_call_count: int = 0
    consecutive_failures: int = 0
    web_search_count: int = 0
    
    # Dedup
    seen_tool_calls: set[str] = field(default_factory=set)
    
    # Last results for fallback
    last_web_search_query: str = ""
    last_web_search_result: Optional[dict[str, Any]] = None
    last_cve_catalog_result: Optional[dict[str, Any]] = None
    
    # Timing
    start_time: float = field(default_factory=time.time)
    total_tokens: int = 0
    
    def should_dedup(self, call_key: str) -> bool:
        """Check if this tool call should be deduplicated."""
        return call_key in self.seen_tool_calls
    
    def register_tool_call(self, call_key: str, tool_name: str, tool_result: dict[str, Any], action_input: dict[str, Any]) -> None:
        """Register a completed tool call."""
        self.seen_tool_calls.add(call_key)
        self.tool_call_count += 1
        
        if tool_name == "web_search" and tool_result.get("success"):
            self.web_search_count += 1
            self.last_web_search_query = str(action_input.get("query", "")).strip()
            self.last_web_search_result = tool_result
        
        if tool_name == "cve_catalog" and tool_result.get("success"):
            self.last_cve_catalog_result = tool_result
    
    def get_fallback_answer(self, thought: str = "") -> str:
        """Get fallback answer based on last results."""
        if self.last_web_search_result is not None:
            from app.agent.react import _build_web_search_fallback
            return _build_web_search_fallback(self.last_web_search_query, self.last_web_search_result)
        if self.last_cve_catalog_result is not None:
            from app.agent.react import _build_cve_catalog_fallback
            return _build_cve_catalog_fallback(self.last_cve_catalog_result)
        return thought or "基于已有信息，我无法获得更多数据，请尝试换个角度提问。"
    
    def get_fallback_confidence(self) -> float:
        """Get confidence for fallback answers."""
        if self.last_web_search_result is not None or self.last_cve_catalog_result is not None:
            return 0.5
        return 0.3
```

### 修改 react.py

使用 `LoopState` 简化 `run` 和 `run_streaming` 方法，消除重复的 dedup/limit/fallback 逻辑。

- [ ] **Step 1: 创建 loop_state.py**

- [ ] **Step 2: 重构 run 方法使用 LoopState**

- [ ] **Step 3: 重构 run_streaming 方法使用 LoopState**

- [ ] **Step 4: 修复 web_search_count 重复递增 bug**

- [ ] **Step 5: 运行测试验证**

Run: `PYTHONPATH=backend pytest tests/test_react_agent.py -v`

- [ ] **Step 6: Commit**

```bash
git add backend/app/agent/loop_state.py backend/app/agent/react.py
git commit -m "refactor: 提取 ReAct 循环公共逻辑到 LoopState，消除代码重复"
```

---

## Task 2: 添加工具结果缓存

**Covers:** F2 性能优化

**Files:**
- Create: `backend/app/agent/tool_cache.py`
- Modify: `backend/app/tools/registry.py`

### 设计

```python
# backend/app/agent/tool_cache.py
"""Tool result cache with TTL and LRU eviction."""

from __future__ import annotations

import hashlib
import json
import time
from collections import OrderedDict
from typing import Any, Optional


class ToolCache:
    """LRU cache for tool results with TTL."""
    
    def __init__(self, max_size: int = 100, ttl_seconds: int = 300):
        self._cache: OrderedDict[str, tuple[dict[str, Any], float]] = OrderedDict()
        self._max_size = max_size
        self._ttl_seconds = ttl_seconds
    
    def _make_key(self, tool_name: str, arguments: dict[str, Any]) -> str:
        """Generate cache key from tool name and arguments."""
        content = json.dumps({"tool": tool_name, "args": arguments}, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def get(self, tool_name: str, arguments: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Get cached result if available and not expired."""
        key = self._make_key(tool_name, arguments)
        if key not in self._cache:
            return None
        
        result, timestamp = self._cache[key]
        if time.time() - timestamp > self._ttl_seconds:
            del self._cache[key]
            return None
        
        # Move to end (most recently used)
        self._cache.move_to_end(key)
        return result
    
    def set(self, tool_name: str, arguments: dict[str, Any], result: dict[str, Any]) -> None:
        """Cache a tool result."""
        key = self._make_key(tool_name, arguments)
        self._cache[key] = (result, time.time())
        self._cache.move_to_end(key)
        
        # Evict oldest if over capacity
        while len(self._cache) > self._max_size:
            self._cache.popitem(last=False)
    
    def clear(self) -> None:
        """Clear all cached results."""
        self._cache.clear()
    
    def stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        return {
            "size": len(self._cache),
            "max_size": self._max_size,
            "ttl_seconds": self._ttl_seconds,
        }


# Global instance
_tool_cache: Optional[ToolCache] = None


def get_tool_cache() -> ToolCache:
    global _tool_cache
    if _tool_cache is None:
        _tool_cache = ToolCache(max_size=100, ttl_seconds=300)
    return _tool_cache
```

### 修改 registry.py

在 `ToolRegistry.execute` 中集成缓存：

```python
# 在 execute 方法中添加缓存检查
async def execute(self, name: str, arguments: dict[str, Any], trace_id: str, tenant_id: str = "system") -> dict[str, Any]:
    # Check cache first (skip for side-effect tools)
    cacheable_tools = {"cve_lookup", "ioc_lookup", "ip_threat_analysis", "whois_lookup", "dns_lookup", "ssl_lookup", "hash_lookup"}
    if name in cacheable_tools:
        cached = get_tool_cache().get(name, arguments)
        if cached:
            logger.info("Tool '%s' cache hit", name)
            return cached
    
    # ... existing execution logic ...
    
    # Cache successful results
    if result.get("success") and name in cacheable_tools:
        get_tool_cache().set(name, arguments, result)
    
    return result
```

- [ ] **Step 1: 创建 tool_cache.py**

- [ ] **Step 2: 修改 registry.py 集成缓存**

- [ ] **Step 3: 运行测试**

Run: `PYTHONPATH=backend pytest tests/test_tool_registry.py -v`

- [ ] **Step 4: Commit**

```bash
git add backend/app/agent/tool_cache.py backend/app/tools/registry.py
git commit -m "feat: 添加工具结果 LRU 缓存，支持 TTL 过期"
```

---

## Task 3: 添加重试机制

**Covers:** F3 稳定性增强

**Files:**
- Create: `backend/app/agent/retry.py`
- Modify: `backend/app/tools/registry.py`

### 设计

```python
# backend/app/agent/retry.py
"""Retry logic with exponential backoff."""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class RetryConfig:
    """Retry configuration."""
    
    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 10.0,
        exponential_base: float = 2.0,
        retryable_exceptions: tuple[type[Exception], ...] = (ConnectionError, TimeoutError),
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.retryable_exceptions = retryable_exceptions


async def retry_async(
    func: Callable[..., Any],
    *args: Any,
    config: Optional[RetryConfig] = None,
    **kwargs: Any,
) -> Any:
    """Execute async function with retry logic."""
    if config is None:
        config = RetryConfig()
    
    last_exception = None
    
    for attempt in range(config.max_retries + 1):
        try:
            return await func(*args, **kwargs)
        except config.retryable_exceptions as e:
            last_exception = e
            if attempt < config.max_retries:
                delay = min(
                    config.base_delay * (config.exponential_base ** attempt),
                    config.max_delay,
                )
                jitter = random.uniform(0, delay * 0.1)
                delay += jitter
                
                logger.warning(
                    "Retry %d/%d for %s after %.1fs: %s",
                    attempt + 1,
                    config.max_retries,
                    func.__name__,
                    delay,
                    str(e),
                )
                await asyncio.sleep(delay)
            else:
                logger.error(
                    "Max retries (%d) exceeded for %s: %s",
                    config.max_retries,
                    func.__name__,
                    str(e),
                )
    
    raise last_exception
```

### 修改 registry.py

在 `ToolRegistry.execute` 中添加重试：

```python
from app.agent.retry import retry_async, RetryConfig

# 工具级重试配置
TOOL_RETRY_CONFIGS: dict[str, RetryConfig] = {
    "web_search": RetryConfig(max_retries=2, base_delay=0.5),
    "threat_intel": RetryConfig(max_retries=2, base_delay=1.0),
    "ioc_lookup": RetryConfig(max_retries=2, base_delay=0.5),
    "nmap_scan": RetryConfig(max_retries=1, base_delay=2.0),
}

async def execute(self, name: str, arguments: dict[str, Any], trace_id: str, tenant_id: str = "system") -> dict[str, Any]:
    # ... existing logic ...
    
    retry_config = TOOL_RETRY_CONFIGS.get(name)
    
    try:
        if retry_config:
            result = await retry_async(tool.execute, input_data, config=retry_config)
        else:
            result = await tool.execute(input_data)
    except Exception as e:
        return ToolResult(
            success=False,
            tool_name=name,
            error=f"Tool execution failed after retries: {e}",
            # ... other fields
        ).model_dump()
    
    return result.model_dump()
```

- [ ] **Step 1: 创建 retry.py**

- [ ] **Step 2: 修改 registry.py 集成重试**

- [ ] **Step 3: 运行测试**

Run: `PYTHONPATH=backend pytest tests/test_tool_registry.py -v`

- [ ] **Step 4: Commit**

```bash
git add backend/app/agent/retry.py backend/app/tools/registry.py
git commit -m "feat: 添加工具执行重试机制，支持指数退避"
```

---

## Task 4: 添加单元测试

**Covers:** F4 测试覆盖

**Files:**
- Create: `tests/test_loop_state.py`
- Create: `tests/test_tool_cache.py`
- Create: `tests/test_retry.py`

- [ ] **Step 1: 创建 loop_state 测试**

```python
# tests/test_loop_state.py
from app.agent.loop_state import LoopState


def test_loop_state_initial():
    state = LoopState()
    assert state.tool_call_count == 0
    assert state.consecutive_failures == 0
    assert len(state.seen_tool_calls) == 0


def test_register_tool_call():
    state = LoopState()
    state.register_tool_call("key1", "ioc_lookup", {"success": True}, {"value": "1.2.3.4"})
    assert state.tool_call_count == 1
    assert "key1" in state.seen_tool_calls
    assert state.last_web_search_result is None


def test_register_web_search():
    state = LoopState()
    state.register_tool_call("key1", "web_search", {"success": True}, {"query": "test"})
    assert state.web_search_count == 1
    assert state.last_web_search_query == "test"


def test_should_dedup():
    state = LoopState()
    assert not state.should_dedup("key1")
    state.seen_tool_calls.add("key1")
    assert state.should_dedup("key1")
```

- [ ] **Step 2: 创建 tool_cache 测试**

```python
# tests/test_tool_cache.py
import time
from app.agent.tool_cache import ToolCache


def test_cache_set_get():
    cache = ToolCache(max_size=10, ttl_seconds=60)
    cache.set("tool1", {"arg": "val"}, {"success": True})
    result = cache.get("tool1", {"arg": "val"})
    assert result == {"success": True}


def test_cache_miss():
    cache = ToolCache()
    result = cache.get("tool1", {"arg": "val"})
    assert result is None


def test_cache_expiry():
    cache = ToolCache(ttl_seconds=0)
    cache.set("tool1", {"arg": "val"}, {"success": True})
    time.sleep(0.1)
    result = cache.get("tool1", {"arg": "val"})
    assert result is None


def test_cache_eviction():
    cache = ToolCache(max_size=2)
    cache.set("t1", {}, {"v": 1})
    cache.set("t2", {}, {"v": 2})
    cache.set("t3", {}, {"v": 3})
    assert cache.get("t1", {}) is None
    assert cache.get("t3", {}) is not None
```

- [ ] **Step 3: 创建 retry 测试**

```python
# tests/test_retry.py
import pytest
from app.agent.retry import retry_async, RetryConfig


@pytest.mark.asyncio
async def test_retry_success_first():
    call_count = 0
    
    async def success_func():
        nonlocal call_count
        call_count += 1
        return "ok"
    
    result = await retry_async(success_func, config=RetryConfig(max_retries=3))
    assert result == "ok"
    assert call_count == 1


@pytest.mark.asyncio
async def test_retry_success_after_failure():
    call_count = 0
    
    async def eventually_success():
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise ConnectionError("transient")
        return "ok"
    
    result = await retry_async(eventually_success, config=RetryConfig(max_retries=3, base_delay=0.01))
    assert result == "ok"
    assert call_count == 3
```

- [ ] **Step 4: 运行所有测试**

Run: `PYTHONPATH=backend pytest tests/test_loop_state.py tests/test_tool_cache.py tests/test_retry.py -v`

- [ ] **Step 5: Commit**

```bash
git add tests/test_loop_state.py tests/test_tool_cache.py tests/test_retry.py
git commit -m "test: 添加 LoopState、ToolCache、Retry 单元测试"
```

---

## 执行顺序

| Task | 内容 | 预计时间 |
|------|------|----------|
| 1 | 代码重构 - 提取 LoopState | 30 分钟 |
| 2 | 工具结果缓存 | 15 分钟 |
| 3 | 重试机制 | 15 分钟 |
| 4 | 单元测试 | 15 分钟 |

**总计：75 分钟**
