# ADR-002: Celery Priority Queue Design

## Status
Accepted

## Context
Agent 系统中有多种异步任务，优先级不同：
- 用户实时查询（高优先级）
- 后台 RAG 索引（低优先级）
- 定时威胁情报更新（中优先级）

需要一种机制区分任务优先级。

## Decision
使用 Celery + Redis 的优先级队列方案：

- `high_priority` 队列：用户交互任务
- `default` 队列：常规任务
- `low_priority` 队列：后台批量任务

通过 Redis 的 List 结构实现，Worker 按优先级顺序消费。

## Consequences

### 正面
- 用户交互任务不会被后台任务阻塞
- 实现简单，不引入额外依赖

### 负面
- 低优先级任务可能长时间不被执行
- 需要合理配置 Worker 数量

### 约束
- 所有异步任务必须经过 Task Dispatcher
- 禁止直接调用 `celery.delay()`
- 任务必须声明优先级
