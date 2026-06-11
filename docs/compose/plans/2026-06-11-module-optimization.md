# 模块优化实施计划

> **For agentic workers:** Use compose:subagent or compose:execute to implement this plan task-by-task.

**Goal:** 优化 LLM Router、RAG Pipeline 和 Multi-Agent 模块

**Architecture:** 添加缓存层 + 代码重构

**Tech Stack:** Python 3.12 + FastAPI

---

## Task 1: LLM Router 添加响应缓存

**Covers:** F1 LLM 调用性能优化

**Files:**
- Create: `backend/app/llm/cache.py`
- Modify: `backend/app/llm/router.py`

### 设计

```python
# backend/app/llm/cache.py
"""LLM response cache to avoid redundant API calls."""

from __future__ import annotations

import hashlib
import json
import time
from collections import OrderedDict
from typing import Any, Optional


class LLMCache:
    """LRU cache for LLM responses with TTL."""

    def __init__(self, max_size: int = 50, ttl_seconds: int = 600):
        self._cache: OrderedDict[str, tuple[dict[str, Any], float]] = OrderedDict()
        self._max_size = max_size
        self._ttl_seconds = ttl_seconds
        self._hits = 0
        self._misses = 0

    def _make_key(self, messages: list[dict[str, Any]], model: str, temperature: float) -> str:
        """Generate cache key from request parameters."""
        content = json.dumps({
            "messages": messages,
            "model": model,
            "temperature": temperature,
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def get(self, messages: list[dict[str, Any]], model: str, temperature: float) -> Optional[dict[str, Any]]:
        """Get cached response if available."""
        key = self._make_key(messages, model, temperature)
        if key not in self._cache:
            self._misses += 1
            return None

        response, timestamp = self._cache[key]
        if time.time() - timestamp > self._ttl_seconds:
            del self._cache[key]
            self._misses += 1
            return None

        self._cache.move_to_end(key)
        self._hits += 1
        return response

    def set(self, messages: list[dict[str, Any]], model: str, temperature: float, response: dict[str, Any]) -> None:
        """Cache an LLM response."""
        key = self._make_key(messages, model, temperature)
        self._cache[key] = (response, time.time())
        self._cache.move_to_end(key)

        while len(self._cache) > self._max_size:
            self._cache.popitem(last=False)

    def stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        total = self._hits + self._misses
        return {
            "size": len(self._cache),
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self._hits / total, 3) if total > 0 else 0.0,
        }


_llm_cache: Optional[LLMCache] = None


def get_llm_cache() -> LLMCache:
    global _llm_cache
    if _llm_cache is None:
        _llm_cache = LLMCache(max_size=50, ttl_seconds=600)
    return _llm_cache
```

### 修改 router.py

在 `complete()` 方法中集成缓存：

```python
async def complete(self, request: LLMRequest) -> LLMResponse:
    """同步调用（非 streaming）with caching"""
    # Check cache for non-streaming requests
    cache = get_llm_cache()
    cached = cache.get(request.messages, request.model or self.default_model, request.temperature)
    if cached:
        logger.info("LLM cache hit for trace=%s", request.trace_id)
        return LLMResponse(**cached)

    # ... existing logic ...

    # Cache successful response
    response_dict = llm_response.model_dump()
    cache.set(request.messages, request.model or self.default_model, request.temperature, response_dict)

    return llm_response
```

- [ ] **Step 1: 创建 llm/cache.py**

- [ ] **Step 2: 修改 router.py 集成缓存**

- [ ] **Step 3: 添加测试**

- [ ] **Step 4: Commit**

---

## Task 2: RAG Pipeline 添加查询缓存

**Covers:** F2 RAG 检索性能优化

**Files:**
- Create: `backend/app/rag/cache.py`
- Modify: `backend/app/rag/pipeline.py`

### 设计

```python
# backend/app/rag/cache.py
"""RAG query cache for repeated searches."""

from __future__ import annotations

import hashlib
import json
import time
from collections import OrderedDict
from typing import Any, Optional


class RAGCache:
    """LRU cache for RAG query results."""

    def __init__(self, max_size: int = 200, ttl_seconds: int = 300):
        self._cache: OrderedDict[str, tuple[list[dict[str, Any]], float]] = OrderedDict()
        self._max_size = max_size
        self._ttl_seconds = ttl_seconds
        self._hits = 0
        self._misses = 0

    def _make_key(self, query: str, top_k: int) -> str:
        """Generate cache key from query parameters."""
        content = json.dumps({"query": query, "top_k": top_k}, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def get(self, query: str, top_k: int) -> Optional[list[dict[str, Any]]]:
        """Get cached results if available."""
        key = self._make_key(query, top_k)
        if key not in self._cache:
            self._misses += 1
            return None

        results, timestamp = self._cache[key]
        if time.time() - timestamp > self._ttl_seconds:
            del self._cache[key]
            self._misses += 1
            return None

        self._cache.move_to_end(key)
        self._hits += 1
        return results

    def set(self, query: str, top_k: int, results: list[dict[str, Any]]) -> None:
        """Cache query results."""
        key = self._make_key(query, top_k)
        self._cache[key] = (results, time.time())
        self._cache.move_to_end(key)

        while len(self._cache) > self._max_size:
            self._cache.popitem(last=False)

    def stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        total = self._hits + self._misses
        return {
            "size": len(self._cache),
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self._hits / total, 3) if total > 0 else 0.0,
        }


_rag_cache: Optional[RAGCache] = None


def get_rag_cache() -> RAGCache:
    global _rag_cache
    if _rag_cache is None:
        _rag_cache = RAGCache(max_size=200, ttl_seconds=300)
    return _rag_cache
```

### 修改 pipeline.py

在 `retrieve()` 方法中集成缓存：

```python
def retrieve(self, query: str, top_k: int = 4) -> list[dict[str, Any]]:
    """Retrieve with caching."""
    cache = get_rag_cache()
    cached = cache.get(query, top_k)
    if cached:
        logger.info("RAG cache hit for query: %s", query[:50])
        return cached

    # ... existing logic ...

    # Cache results
    cache.set(query, top_k, fused[:top_k])

    return fused[:top_k]
```

- [ ] **Step 1: 创建 rag/cache.py**

- [ ] **Step 2: 修改 pipeline.py 集成缓存**

- [ ] **Step 3: 添加测试**

- [ ] **Step 4: Commit**

---

## Task 3: Multi-Agent 协调器重构

**Covers:** F3 代码结构优化

**Files:**
- Modify: `backend/app/multi_agent/coordinator.py`
- Modify: `backend/app/multi_agent/base_agent.py`

### 优化点

1. **提取公共逻辑** - 将重复的错误处理和日志记录提取到基类
2. **简化任务执行** - 使用 LoopState 模式简化状态管理
3. **改善类型注解** - 添加完整的类型注解

- [ ] **Step 1: 重构 coordinator.py**

- [ ] **Step 2: 改善 base_agent.py**

- [ ] **Step 3: 运行测试**

- [ ] **Step 4: Commit**

---

## Task 4: 添加单元测试

**Covers:** F4 测试覆盖

**Files:**
- Create: `tests/test_llm_cache.py`
- Create: `tests/test_rag_cache.py`
- Create: `tests/test_multi_agent_integration.py`

- [ ] **Step 1: 创建 LLM Cache 测试**

- [ ] **Step 2: 创建 RAG Cache 测试**

- [ ] **Step 3: 创建 Multi-Agent 集成测试**

- [ ] **Step 4: Commit**

---

## 执行顺序

| Task | 内容 | 预计时间 |
|------|------|----------|
| 1 | LLM Router 缓存 | 20 分钟 |
| 2 | RAG Pipeline 缓存 | 15 分钟 |
| 3 | Multi-Agent 重构 | 30 分钟 |
| 4 | 单元测试 | 20 分钟 |

**总计：85 分钟**
