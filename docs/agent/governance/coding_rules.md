# Coding Rules

> 编码约束中心。所有 Agent 必须遵守。

## Backend

| 规则 | 原因 |
|------|------|
| API 层禁止写业务逻辑 | 保持 Controller 薄层 |
| Service 层禁止访问 request | Service 不依赖 HTTP 上下文 |
| Tool 不允许直接操作数据库 | 必须走 Repository 层 |
| 所有 DB 操作走 repository | 统一数据访问层 |
| 禁止在 Handler 中拼 SQL | 防止注入、保持可测试性 |
| 异步任务必须经过 task dispatcher | 统一任务管理 |

## Frontend

| 规则 | 原因 |
|------|------|
| API 请求统一 `services/` | 统一请求管理层 |
| 页面禁止直接 `fetch` | 防止散落的 HTTP 调用 |
| Zustand store 禁止循环依赖 | 防止状态管理死锁 |
| 组件禁止直接操作 localStorage | 统一存储抽象 |

## AI Layer

| 规则 | 原因 |
|------|------|
| 所有 Prompt 必须版本化 | 可追溯、可回滚 |
| Tool 返回必须结构化 | 避免自由文本解析 |
| Agent 不允许直接拼 JSON | 使用 Pydantic model |
| 所有 LLM 调用必须经过 `llm/router.py` | 统一模型路由 |
| 禁止 tools 直接调用模型 | 防止绕过路由层 |
| Tool Schema 变更必须版本化 | 防止隐式漂移 |

## 通用

| 规则 | 原因 |
|------|------|
| 禁止未授权重构 | 防止系统漂移 |
| 新增第三方依赖必须声明理由 | 控制依赖膨胀 |
| 函数不超过 50 行 | 保持可读性 |
| 文件不超过 300 行 | 强制拆分 |
| 命名使用 snake_case (Python) / camelCase (TS) | 语言惯例 |
| 禁止 magic number | 必须定义常量 |
| **新功能必须同步前端页面** | 确保功能完整性，后端实现+测试通过后，必须检查是否需要前端页面，如需要则一并完成设计和实现后再交付 |
