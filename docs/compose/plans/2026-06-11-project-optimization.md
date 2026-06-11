# CyberSec Agent 项目优化实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use compose:subagent (recommended) or compose:execute to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 提升项目代码质量、性能、可维护性和测试覆盖率

**Architecture:** 系统性优化 — 从代码规范 → 错误处理 → 性能优化 → 测试完善 → 文档同步

**Tech Stack:** Python 3.12 + FastAPI + React + TypeScript + PostgreSQL

---

## 项目分析摘要

### 优势
- 模块化架构清晰（23个后端模块 + 17个前端页面）
- 功能丰富（27个工具 + 78个API端点）
- 完整的测试套件（43个测试文件）
- 详细的文档（62份）

### 待优化问题

| 类别 | 问题 | 严重程度 |
|------|------|----------|
| 代码规范 | main.py 版本号不一致（0.5.0 vs 0.9.0） | 中 |
| 错误处理 | 多处 `except: pass` 静默吞异常 | 高 |
| 类型安全 | 部分函数缺少类型注解 | 中 |
| 配置管理 | 硬编码配置散落在代码中 | 中 |
| 测试覆盖 | 部分模块测试缺失 | 中 |
| 性能 | 同步阻塞调用未完全异步化 | 低 |
| 文档 | API文档与实际端点不同步 | 低 |

---

## Task 1: 代码规范修复

**Covers:** F1 代码质量基础

**Files:**
- Modify: `backend/app/main.py`
- Modify: `backend/app/agent/react.py`

- [ ] **Step 1: 修复版本号不一致**

```python
# backend/app/main.py
# 行 162: 将 version="0.5.0" 改为 version="0.9.0"
app = FastAPI(
    title="CyberSec Agent",
    description="网络安全智能分析平台 — ReAct Agent + DeepSeek API + 攻击链溯源 + 关联分析",
    version="0.9.0",  # 修正版本号
    lifespan=lifespan,
)
```

- [ ] **Step 2: 运行测试验证**

Run: `PYTHONPATH=backend pytest tests/test_api_regression.py -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add backend/app/main.py
git commit -m "fix: 修正 FastAPI 版本号为 0.9.0"
```

---

## Task 2: 错误处理优化

**Covers:** F2 异常处理鲁棒性

**Files:**
- Modify: `backend/app/main.py` (行 71-72, 153-154, 179-180)
- Create: `backend/app/core/exceptions.py`

- [ ] **Step 1: 创建自定义异常类**

```python
# backend/app/core/exceptions.py
"""Custom exceptions for CyberSec Agent."""

from __future__ import annotations


class CyberSecException(Exception):
    """Base exception for CyberSec Agent."""
    pass


class DatabaseConnectionError(CyberSecException):
    """Database connection failed."""
    pass


class LLMRouterError(CyberSecException):
    """LLM routing failed."""
    pass


class ToolExecutionError(CyberSecException):
    """Tool execution failed."""
    pass
```

- [ ] **Step 2: 优化 main.py 错误处理**

```python
# backend/app/main.py
# 行 67-72: 数据库初始化
try:
    from app.models.base import init_db
    await init_db()
    logger.info("Database tables initialized")
except Exception as e:
    logger.warning("Database init skipped: %s (PostgreSQL not available)", e)
    # 不再静默，记录具体错误类型
    if "connect" in str(e).lower():
        logger.error("Database connection failed - check DATABASE_URL")
```

- [ ] **Step 3: 优化中间件错误处理**

```python
# backend/app/main.py
# 行 176-180: 审计中间件
try:
    from app.middleware.audit import AuditMiddleware
    app.add_middleware(AuditMiddleware)
except ImportError as e:
    logger.warning("Audit middleware not loaded: %s", e)
except Exception as e:
    logger.error("Audit middleware initialization failed: %s", e)
```

- [ ] **Step 4: 运行测试**

Run: `PYTHONPATH=backend pytest tests/test_config.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/core/exceptions.py backend/app/main.py
git commit -m "refactor: 优化异常处理，添加自定义异常类"
```

---

## Task 3: 配置管理优化

**Covers:** F3 配置可维护性

**Files:**
- Modify: `backend/app/core/config.py`
- Create: `backend/app/core/constants.py`

- [ ] **Step 1: 创建常量文件**

```python
# backend/app/core/constants.py
"""Application constants."""

from __future__ import annotations

# 版本信息
APP_VERSION = "0.9.0"
APP_TITLE = "CyberSec Agent"

# 默认配置
DEFAULT_LLM_MODEL = "deepseek-v4-flash"
DEFAULT_LLM_TIMEOUT = 30
DEFAULT_MAX_TOOL_CALLS = 4
DEFAULT_CONTEXT_WINDOW = 32768

# RAG 配置
RAG_TOP_K = 4
RAG_MAX_OBSERVATION_TOKENS = 2000

# 调查预算
MINI_PLANNER_MAX_STEPS = 4
MINI_PLANNER_MAX_TIME = 60
FULL_PLANNER_MAX_STEPS = 12
FULL_PLANNER_MAX_TIME = 120
```

- [ ] **Step 2: 更新 main.py 使用常量**

```python
# backend/app/main.py
from app.core.constants import APP_VERSION

app = FastAPI(
    title="CyberSec Agent",
    description="网络安全智能分析平台",
    version=APP_VERSION,
    lifespan=lifespan,
)
```

- [ ] **Step 3: 运行测试**

Run: `PYTHONPATH=backend pytest tests/test_config.py -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add backend/app/core/constants.py backend/app/main.py
git commit -m "refactor: 提取应用常量到 constants.py"
```

---

## Task 4: 类型注解完善

**Covers:** F4 类型安全

**Files:**
- Modify: `backend/app/agent/react.py`
- Modify: `backend/app/agent/context.py`

- [ ] **Step 1: 完善 react.py 类型注解**

```python
# backend/app/agent/react.py
# 行 28-34: ReActResult 已有类型注解，检查其他函数
# 确保所有公共函数都有完整的类型注解
```

- [ ] **Step 2: 完善 context.py 类型注解**

```python
# 检查 context.py 中的函数签名
# 确保参数和返回值都有类型注解
```

- [ ] **Step 3: 运行类型检查**

Run: `cd frontend && npx tsc --noEmit`
Expected: No errors

Run: `PYTHONPATH=backend python -m py_compile backend/app/agent/react.py`
Expected: No errors

- [ ] **Step 4: Commit**

```bash
git add backend/app/agent/react.py backend/app/agent/context.py
git commit -m "style: 完善 agent 模块类型注解"
```

---

## Task 5: 测试覆盖率提升

**Covers:** F5 测试完善

**Files:**
- Create: `tests/test_constants.py`
- Create: `tests/test_exceptions.py`

- [ ] **Step 1: 创建常量测试**

```python
# tests/test_constants.py
"""Tests for application constants."""

from app.core.constants import (
    APP_VERSION,
    DEFAULT_LLM_MODEL,
    DEFAULT_MAX_TOOL_CALLS,
    RAG_TOP_K,
)


def test_app_version():
    assert APP_VERSION == "0.9.0"


def test_default_llm_model():
    assert DEFAULT_LLM_MODEL == "deepseek-v4-flash"


def test_max_tool_calls():
    assert DEFAULT_MAX_TOOL_CALLS == 4


def test_rag_top_k():
    assert RAG_TOP_K == 4
```

- [ ] **Step 2: 创建异常测试**

```python
# tests/test_exceptions.py
"""Tests for custom exceptions."""

from app.core.exceptions import (
    CyberSecException,
    DatabaseConnectionError,
    LLMRouterError,
    ToolExecutionError,
)


def test_exception_hierarchy():
    assert issubclass(DatabaseConnectionError, CyberSecException)
    assert issubclass(LLMRouterError, CyberSecException)
    assert issubclass(ToolExecutionError, CyberSecException)


def test_exception_message():
    exc = DatabaseConnectionError("Connection failed")
    assert str(exc) == "Connection failed"
```

- [ ] **Step 3: 运行新测试**

Run: `PYTHONPATH=backend pytest tests/test_constants.py tests/test_exceptions.py -v`
Expected: 6 tests PASS

- [ ] **Step 4: Commit**

```bash
git add tests/test_constants.py tests/test_exceptions.py
git commit -m "test: 添加常量和异常类的单元测试"
```

---

## Task 6: 文档同步

**Covers:** F6 文档维护

**Files:**
- Modify: `README.md`
- Modify: `PROJECT_SUMMARY.md`

- [ ] **Step 1: 更新 README.md 版本信息**

```markdown
# 在 README.md 中确认版本号一致
当前版本：v0.9.0（Phase 5 — 交付准备）
```

- [ ] **Step 2: 更新 PROJECT_SUMMARY.md**

```markdown
# 确认 PROJECT_SUMMARY.md 中的版本信息与 README.md 一致
```

- [ ] **Step 3: 验证 API 端点文档**

```bash
# 启动后端服务后访问
# http://localhost:8000/docs - Swagger 文档
# 确认文档与实际端点一致
```

- [ ] **Step 4: Commit**

```bash
git add README.md PROJECT_SUMMARY.md
git commit -m "docs: 同步项目文档版本信息"
```

---

## 执行顺序建议

| 优先级 | Task | 预计时间 |
|--------|------|----------|
| P0 | Task 1: 代码规范修复 | 5 分钟 |
| P0 | Task 2: 错误处理优化 | 15 分钟 |
| P1 | Task 3: 配置管理优化 | 10 分钟 |
| P1 | Task 4: 类型注解完善 | 10 分钟 |
| P2 | Task 5: 测试覆盖率提升 | 15 分钟 |
| P2 | Task 6: 文档同步 | 5 分钟 |

**总计预计时间：60 分钟**

---

## 执行方式选择

请选择执行方式：

1. **Subagent, always** — 每个任务启动新子代理（推荐，任务独立）
2. **Subagent, this time** — 仅本次使用子代理
3. **Inline, always** — 在当前会话中执行
4. **Inline, this time** — 仅本次在当前会话执行
