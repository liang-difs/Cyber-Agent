# Multi-Agent Protocol

> 多 Agent 协作协议。定义职责边界、共享契约、交接流程。

## Agent Responsibilities

| Agent | 职责范围 | 禁止操作 |
|-------|---------|---------|
| frontend_agent | `frontend/*` | 修改 API、修改 Agent 逻辑 |
| backend_agent | `backend/app/api/*`, `services/*`, `models/*` | 修改前端、修改 Prompt |
| ai_agent | `prompts/*`, `rag/*`, `backend/app/agent/*` | 修改前端、修改 API 层 |
| infra_agent | `infra/*`, `docker-compose.yml`, CI/CD | 修改业务代码 |

## Shared Contracts

以下文件是所有 Agent 的共享契约，修改需要通知所有相关 Agent：

- `tool_protocol.md` — Tool Schema 定义
- `contracts/api/` — API 接口契约
- `contracts/websocket/` — WebSocket 消息契约
- `contracts/tool/` — Tool 接口契约
- `PROJECT_STATE.json` — 项目状态

## Handoff Protocol

Agent 完成任务后必须执行：

1. **更新 PROJECT_STATE.json**
   - 标记完成的任务
   - 更新 current_goal（如阶段变更）
   - 更新 next 列表

2. **更新 known_issues.md**
   - 记录发现的新问题
   - 标记已解决的问题

3. **输出 changed_interfaces.md**
   - 列出本次修改的接口
   - 包含 request/response 格式变更

4. **更新 TECH_DEBT.md**（如有新增技术债）

## 冲突解决

当多个 Agent 需要修改同一文件：

1. 检查 File Ownership（见 runtime_governance.md）
2. 如果超出 ownership 范围，必须提出修改请求
3. 由 governance_agent 或人类审批
4. 修改后通知所有相关 Agent

## 上下文隔离

每个 Agent 只加载自己需要的上下文：

- `frontend_agent`: 前端代码 + API contracts
- `backend_agent`: 后端代码 + API contracts + DB schema
- `ai_agent`: Prompt + Tool protocol + RAG 配置
- `infra_agent`: infra 代码 + 部署配置

禁止跨 Agent 上下文加载（防止上下文爆炸）。
