# Dependency Map

> 详细依赖映射。记录模块间的显式和隐式依赖。

## 外部依赖

### Python 核心依赖

| 包 | 用途 | 版本约束 |
|---|------|---------|
| litellm | LLM 统一路由 | ^1.x |
| fastapi | Web 框架 | ^0.100 |
| celery | 异步任务 | ^5.x |
| sqlalchemy | ORM | ^2.x |
| redis | Redis 客户端 | ^5.x |
| pydantic | 数据校验 | ^2.x |
| chromadb | 向量数据库 | ^0.4.x |
| elasticsearch | 搜索引擎 | ^8.x |

### 外部服务依赖

| 服务 | 用途 | 必需 |
|------|------|------|
| PostgreSQL | 主数据库 | Phase 0 |
| Redis | 缓存 + 消息队列 | Phase 0 |
| Claude API | LLM 推理 | Phase 0 |
| ChromaDB | 向量存储 | Phase 1 |
| Elasticsearch | 全文搜索 | Phase 1 |
| Threat Intel API | 威胁情报源 | Phase 2 |

## 内部依赖关系

### 必须依赖（不可解耦）

```
Agent Engine → LLM Router (所有推理必须经过 Router)
Agent Engine → Tool Registry (所有工具调用必须经过 Registry)
Task Dispatcher → Redis (队列存储)
RAG Engine → ChromaDB (向量检索)
```

### 可选依赖（可降级）

```
Agent Engine → Context Manager (可降级为无状态模式)
RAG Engine → Elasticsearch (可降级为仅 ChromaDB)
Tool → Threat Intel API (可降级为本地缓存)
```

## 依赖禁止

| 禁止的依赖 | 原因 |
|-----------|------|
| Tool → LLM Router | Tool 不得直接调用模型 |
| API 层 → Repository | 必须经过 Service 层 |
| Frontend → 后端内部 | 必须经过 API |
| Celery Worker → API 层 | Worker 不得调用 HTTP API |

## Phase 0 依赖约束

Phase 0 只允许使用以下依赖：

| 依赖 | 状态 | 说明 |
|------|------|------|
| litellm | 已验证 | LLM 统一路由，Phase 0 核心 |
| fastapi | 已验证 | Web 框架 |
| pydantic | 已验证 | 数据校验 |
| redis | 已验证 | 缓存 + 消息队列 |
| sqlalchemy | 已验证 | ORM |
| celery | 待验证 | 异步任务（Phase 0 可选） |

Phase 0 禁止引入：
- chromadb（Phase 1）
- elasticsearch（Phase 1）
- 任何未在上表中的依赖（需提 ADR）
