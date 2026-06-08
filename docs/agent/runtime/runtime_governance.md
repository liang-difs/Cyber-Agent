# Runtime Governance

> Agent 运行时行为护栏。违反此文件中的规则 = 立即停止。

## Agent Allowed Actions

### 可以做的
- 创建新文件（遵循 coding_rules.md）
- 修改 `tests/` 目录下的文件
- 修改 `docs/agent/` 目录下的治理文件
- 更新 `PROJECT_STATE.json`
- 更新 `TECH_DEBT.md` 和 `known_issues.md`

### 不可以做的
- 删除 `infra/` 下任何文件
- 修改 `docker-compose.yml`
- 修改 `.env` 文件
- 修改 CI/CD 配置文件
- 直接修改数据库 schema（必须先提方案）

## Phase 0 硬约束（当前生效）

> 以下约束在 Phase 0 期间绝对不可违反。

| 约束 | 原因 |
|------|------|
| 禁止实现业务代码 | Phase 0 目标是验证基础设施，不是写业务 |
| 禁止新增第三方依赖 | 依赖列表已冻结，变更需提 ADR |
| 禁止创建 API 端点 | API 设计未定稿，禁止提前实现 |
| 禁止修改 infra 配置 | 基础设施已验证通过，不可动 |
| 禁止写前端页面 | 前端架构未定 |
| 禁止跨阶段开发 | Phase 0 不做 Phase 1 的事 |

## Forbidden Autonomous Behaviors

| 行为 | 原因 |
|------|------|
| 禁止未授权重构 | 防止系统漂移 |
| 禁止主动升级依赖 | 防止兼容性破坏 |
| 禁止跨阶段开发 | Phase 0 不做 Phase 1 的事 |
| 禁止修改稳定 API | 已验证的接口不可动 |
| 禁止"顺手优化" | 除非有明确 ticket |

## High-Risk Operations

以下操作 **必须先提出方案，获得确认后才能执行**：

1. DB Schema 修改
2. Tool Protocol 修改
3. Prompt Schema 修改
4. 新增 Redis Key Pattern
5. 修改 RAG 检索逻辑
6. 修改 Agent 状态机结构
7. 新增第三方依赖

## File Ownership

```
frontend/*          → frontend_agent
backend/app/agent/* → ai_agent
backend/app/api/*   → backend_agent
infra/*             → infra_agent
docs/agent/*        → governance_agent (或当前活跃 agent)
prompts/*           → ai_agent
```

## Agent 行为边界

### 允许的决策
- 选择具体实现方式（在约束范围内）
- 选择变量命名、文件命名
- 选择测试用例的组织方式

### 禁止的决策
- 架构变更（必须提 ADR）
- 新增/删除模块
- 修改模块间依赖关系
- 更换技术栈组件
