# ADR-003: RAG Multi-Tenant Isolation

## Status
Accepted

## Context
RAG 系统需要支持多租户，每个租户的文档和检索结果必须隔离。最危险的场景是 `tenant_id` 漏过滤，导致跨租户数据泄露。

## Decision
在底层封死租户隔离，不依赖 Prompt 或上层逻辑：

1. **ChromaDB**: 使用 `collection` 级别隔离，每个租户一个 collection
2. **Elasticsearch**: 所有查询强制注入 `tenant_id` filter
3. **Repository 层**: 封装租户过滤逻辑，上层无法绕过

## Consequences

### 正面
- 即使上层代码有 bug，也不会泄露跨租户数据
- 统一隔离逻辑，无需在每个查询点重复过滤

### 负面
- 每个租户独立 collection 会有一定的存储开销
- 跨租户查询（管理员场景）需要特殊处理

### 约束
- 禁止在 RAG 查询中手动拼接 tenant_id filter
- 所有 RAG 操作必须经过 Repository 层
- 租户隔离逻辑的修改属于 High-Risk Operation
