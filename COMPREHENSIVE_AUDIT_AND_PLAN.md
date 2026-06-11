# CyberSec Agent 全面审查报告与优化落地计划

> 审查日期：2026-06-11 | 审查范围：后端/前端/测试/基础设施/安全

---

## 一、审查总览

| 维度 | 评级 | 关键问题数 |
|------|------|-----------|
| **安全** | 🔴 高风险 | 12 |
| **代码质量** | 🟡 中等 | 18 |
| **性能** | 🟡 中等 | 10 |
| **架构** | 🟡 中等 | 8 |
| **测试** | 🟡 覆盖不足 | 6 |
| **基础设施** | 🟡 需加固 | 9 |

---

## 二、安全问题（按严重度排序）

### CRITICAL

| # | 问题 | 位置 | 影响 |
|---|------|------|------|
| S1 | **API 密钥泄露** — `.env` 文件含真实密钥（DeepSeek/VT/OTX/AbuseIPDB/NVD），可能已被 git 跟踪 | `.env` + git history | 所有外部 API 可被盗用 |
| S2 | **空 JWT 密钥** — `jwt_secret` 默认为空字符串，开发环境可伪造 Token | `core/config.py:98` | 身份认证完全失效 |
| S3 | **硬编码数据库凭据** — `cybersec:cybersec_pass` 出现在 config/docker-compose/alembic/启动脚本 | 多处 | 默认凭据可直接登录 |

### HIGH

| # | 问题 | 位置 | 影响 |
|---|------|------|------|
| S4 | **XSS 漏洞** — ReactMarkdown 未启用 `rehype-sanitize`，用户输入/LLM 输出直接渲染 HTML | `ResponseCards/index.tsx:29,48` | 存储型 XSS |
| S5 | **审计日志跳过 Agent 通信** — `/api/v1/agent/chat` 和 `/api/v1/agent/sessions` 被排除在审计之外 | `middleware/audit.py:19-27` | 合规缺口 |
| S6 | **Sanitizer 管线未接入** — PII 脱敏管线已实现但从未在 ReAct 循环中调用 | `sanitizer/pipeline.py` | 敏感数据直通 LLM |
| S7 | **Elasticsearch 安全关闭** — `xpack.security.enabled=false` | `infra/docker-compose.yml` | ES 数据无认证访问 |
| S8 | **Nginx 无 TLS/安全头** — 无 HTTPS、无 CSP、无 rate limiting | `frontend/nginx.conf` | 中间人攻击/注入 |
| S9 | **WebSocket JWT 在 URL 中** — Token 作为查询参数传递，可被日志/历史记录捕获 | `hooks/useWebSocket.ts:18` | Token 泄露 |
| S10 | **RBAC 未在工具层执行** — VIEWER 角色可通过 WebSocket 绕过 HTTP 中间件调用任意工具 | `rbac/permissions.py` + `tools/registry.py` | 权限绕过 |
| S11 | **后端 Dockerfile 以 root 运行** — 容器内无非 root 用户 | `backend/Dockerfile` | 容器逃逸扩大影响 |
| S12 | **基础设施端口暴露** — PostgreSQL/Redis/ES 端口绑定到所有网络接口 | `infra/docker-compose.yml` | 内部服务外部可访问 |

---

## 三、代码质量问题

### 后端

| # | 问题 | 位置 | 严重度 |
|---|------|------|--------|
| Q1 | **react.py 过长 (1239行)** — run() 和 run_streaming() 逻辑大量重复 | `agent/react.py` | HIGH |
| Q2 | **SYSTEM_PROMPT 硬编码 (310行)** — 混入业务逻辑 | `agent/react.py:47-358` | MEDIUM |
| Q3 | **decision_trace.py DB 持久化失效** — `loop.is_running()` 检查导致生产环境永远走内存路径 | `agent/decision_trace.py:124-186` | HIGH |
| Q4 | **evidence_store.py 未被使用** — 证据存证系统已实现但 react.py 从未调用 | `agent/evidence_store.py` | HIGH |
| Q5 | **全局单例无内存上限** — decision_tracker/EvidenceStore 的 _collections 无限增长 | 多处 | MEDIUM |
| Q6 | **constants.py 值冲突** — `DEFAULT_MAX_TOOL_CALLS=4` vs react.py 的 `MAX_TOOL_CALLS=10`；JWT_EXPIRY 24h vs config 60min | `core/constants.py` | MEDIUM |
| Q7 | **LLMCache 多进程失效** — 单进程 OrderedDict，多 worker 部署时缓存不共享 | `llm/cache.py` | MEDIUM |
| Q8 | **循环依赖** — loop_state.py ↔ react.py 双向导入 | `agent/` | LOW |
| Q9 | **main.py 第 101-102 行缩进错误** — `from app.core.config import get_settings` 和 `from app.core.constants import APP_VERSION` 缩进不一致 | `main.py:101-102` | HIGH |

### 前端

| # | 问题 | 位置 | 严重度 |
|---|------|------|--------|
| Q10 | **大量 `any` 类型** — TaskStatus.result, ChatMessage.toolCalls/metadata, Alert.severity 等 8+ 处 | `types/api.ts` | MEDIUM |
| Q11 | **无 React.memo/useMemo** — 所有组件均未做性能优化 | 全局 | MEDIUM |
| Q12 | **Report 下载函数重复 4 次** — PDF/DOCX × 标准/PCAP | `api/report.ts:53-125` | LOW |
| Q13 | **错误提取模式重复 10+ 次** — `err.response?.data?.detail` | 所有页面 | LOW |
| Q14 | **Route 列表重复定义 3 次** — App.tsx/RoleGuard/AppLayout | 3 个文件 | LOW |
| Q15 | **无请求取消** — useEffect 中异步函数无 cleanup | 所有页面 | MEDIUM |
| Q16 | **parseNumericScore/getScoreColor 重复** — IpCard/IocCard 各自实现 | `components/ResponseCards/` | LOW |
| Q17 | **无 i18n** — 所有中文字符串硬编码 | 全局 | LOW |

---

## 四、性能问题

| # | 问题 | 位置 | 严重度 |
|---|------|------|--------|
| P1 | **上下文压缩质量差** — 仅截断拼接，未使用 LLM 摘要 | `agent/context_compressor.py:230-278` | MEDIUM |
| P2 | **Token 估算不准确** — `len(text)//4` 对中文严重低估 | `agent/context_compressor.py:17` | MEDIUM |
| P3 | **时间测量不单调** — 使用 `time.time()` 而非 `time.monotonic()` | `agent/react.py:834,961` | LOW |
| P4 | **MessageList 每次渲染都重新过滤** — O(n*m) 工具执行过滤在 `.map()` 内 | `pages/Chat/MessageList.tsx:25,31` | MEDIUM |
| P5 | **LLM 用量事件截断 O(n)** — `del self.usage_events[:500]` | `llm/router.py:339-340` | LOW |
| P6 | **json.dumps 多次调用** — compact_tool_observation 最多 4 次序列化 | `agent/context_compressor.py:208-222` | LOW |
| P7 | **无请求去重** — 多页面轮询同一端点 | Dashboard/Monitor/Chat | LOW |
| P8 | **Nginx 无 gzip** — 未配置响应压缩 | `frontend/nginx.conf` | LOW |

---

## 五、架构问题

| # | 问题 | 说明 | 严重度 |
|---|------|------|--------|
| A1 | **EvidenceStore 与 react.py 脱节** — 设计了完整的证据存证系统但 ReAct 循环未集成 | 功能缺失 | HIGH |
| A2 | **Sanitizer 管线断裂** — pipeline.py 已实现但未在数据流中接入 | 安全缺失 | HIGH |
| A3 | **单体迁移** — 8 张表在一个迁移文件中，无法独立回滚 | 维护困难 | MEDIUM |
| A4 | **前端无集中状态管理** — 除 auth/chat/theme 外所有页面用 useState 管理 CRUD | 架构不一致 | MEDIUM |
| A5 | **无数据获取库** — 每个页面手动管理 loading/error/data 状态，约 40% 样板代码 | 效率低 | MEDIUM |
| A6 | **全局单例无隔离** — 多租户环境下 evidence_store/decision_tracker 可能跨租户泄露 | 隔离不完整 | MEDIUM |

---

## 六、测试缺口

| 模块 | 状态 | 说明 |
|------|------|------|
| User CRUD API | ❌ 无测试 | users.py 路由完全未覆盖 |
| WebSocket 完整流程 | ⚠️ 部分 | 仅测试连接拒绝，无完整对话流程 |
| Celery 任务执行 | ⚠️ 部分 | 仅测试注册和 delay mock |
| Elasticsearch 集成 | ❌ 无测试 | 无搜索/索引测试 |
| MinIO/S3 集成 | ❌ 无测试 | 无文件上传/下载测试 |
| Coverage 配置 | ❌ 缺失 | 无 `.coveragerc`，无 `--cov` 参数 |
| 数据库 Fixtures | ❌ 缺失 | 测试手动调用 close_db() |
| pytest markers | ❌ 未注册 | `@pytest.mark.anyio` 产生警告 |

---

## 七、落地计划

### Phase 1：安全加固（优先级 P0，预计 3-5 天）

| 任务 | 工作量 | 文件 |
|------|--------|------|
| **1.1** 轮换所有泄露的 API 密钥，确保 `.env` 不进入 git | 0.5天 | `.env`, git history |
| **1.2** JWT 密钥：开发环境生成随机密钥，生产强制配置 | 0.5天 | `core/config.py` |
| **1.3** 接入 Sanitizer 到 ReAct 循环 | 1天 | `agent/react.py`, `sanitizer/pipeline.py` |
| **1.4** 启用 ReactMarkdown sanitize 插件 | 0.5天 | `ResponseCards/index.tsx`, `Reports/index.tsx` |
| **1.5** 审计日志覆盖 Agent 通信端点 | 0.5天 | `middleware/audit.py` |
| **1.6** 启用 Elasticsearch 安全认证 | 0.5天 | `infra/docker-compose.yml` |
| **1.7** Nginx 添加安全头 + rate limiting | 0.5天 | `frontend/nginx.conf` |

### Phase 2：核心代码质量（P1，预计 5-7 天）

| 任务 | 工作量 | 文件 |
|------|--------|------|
| **2.1** 拆分 react.py — 提取 SYSTEM_PROMPT 到模板文件，合并 run()/run_streaming() 为统一方法 | 2天 | `agent/react.py`, `agent/prompt.py` (新建) |
| **2.2** 修复 decision_trace.py DB 持久化 — 使用 async 正确方式写入 | 1天 | `agent/decision_trace.py` |
| **2.3** 集成 EvidenceStore 到 ReAct 循环 | 1天 | `agent/react.py`, `agent/evidence_store.py` |
| **2.4** 全局单例添加 TTL/大小上限 — decision_tracker 和 evidence_store | 0.5天 | 多处 |
| **2.5** 修复 main.py 缩进错误 | 0.5天 | `main.py:101-102` |
| **2.6** 统一常量定义 — 解决 constants.py 与 react.py/config.py 值冲突 | 0.5天 | `core/constants.py`, `core/config.py` |
| **2.7** LLMCache 支持 Redis 共享缓存 | 1天 | `llm/cache.py` |

### Phase 3：前端优化（P1，预计 3-5 天）

| 任务 | 工作量 | 文件 |
|------|--------|------|
| **3.1** 消除 `any` 类型 — 完善 TypeScript 类型定义 | 1天 | `types/api.ts`, 多个页面 |
| **3.2** 提取公共工具函数 — 错误处理/分数计算/报告下载 | 1天 | `utils/`, 多个页面 |
| **3.3** 添加 React.memo/useMemo 优化热点组件 | 1天 | `MessageList`, `ResponseCards` |
| **3.4** 添加请求取消 (AbortController) | 0.5天 | 所有页面 useEffect |
| **3.5** 统一路由定义 — 消除 3 处重复 | 0.5天 | `constants/routes.ts` (新建) |
| **3.6** 删除死代码 — ToolProgress/未使用的 props/imports | 0.5天 | 多处 |

### Phase 4：测试补全（P2，预计 3-5 天）

| 任务 | 工作量 | 文件 |
|------|--------|------|
| **4.1** 配置 pytest-cov + 合并 conftest.py fixtures | 0.5天 | `pytest.ini`, `conftest.py` |
| **4.2** 补全 User CRUD API 测试 | 0.5天 | `tests/test_users_api.py` (新建) |
| **4.3** 补全 WebSocket 完整对话流程测试 | 1天 | `tests/test_chat_ws_e2e.py` (新建) |
| **4.4** 补全 Celery 任务执行测试 | 0.5天 | `tests/test_celery_tasks.py` (新建) |
| **4.5** 添加数据库 fixtures (create/drop schema per session) | 1天 | `conftest.py` |
| **4.6** 注册 pytest markers + 添加分类运行 | 0.5天 | `pytest.ini` |

### Phase 5：基础设施加固（P2，预计 2-3 天）

| 任务 | 工作量 | 文件 |
|------|--------|------|
| **5.1** 添加 `.dockerignore` | 0.5天 | `.dockerignore` (新建) |
| **5.2** Dockerfile 添加非 root 用户 | 0.5天 | `backend/Dockerfile`, `frontend/Dockerfile` |
| **5.3** Docker 服务添加资源限制 | 0.5天 | `infra/docker-compose.yml` |
| **5.4** 凭据外部化 — 使用 Docker secrets 或环境变量注入 | 0.5天 | `infra/docker-compose.yml` |
| **5.5** 内部服务端口不暴露到宿主机 | 0.5天 | `infra/docker-compose.yml` |
| **5.6** 启用 Nginx gzip 压缩 | 0.5天 | `frontend/nginx.conf` |

### Phase 6：架构改进（P3，预计 5-7 天）

| 任务 | 工作量 | 文件 |
|------|--------|------|
| **6.1** 引入 React Query / SWR 替代手动状态管理 | 3天 | 全局重构 |
| **6.2** 分离数据库迁移为增量式 | 1天 | `alembic/versions/` |
| **6.3** 前端 i18n 框架接入 | 2天 | 全局 |
| **6.4** CI/CD 管线搭建 (GitHub Actions) | 1天 | `.github/workflows/` |

---

## 八、优先级矩阵

```
         高影响
          │
  Phase 1 │ Phase 2
 (安全加固)│ (代码质量)
          │
──────────┼──────────
          │
  Phase 5 │ Phase 3
 (基础设施)│ (前端优化)
          │
         低影响
  高紧急 ←──────→ 低紧急
```

**建议执行顺序：** Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5 → Phase 6

**预计总工作量：** 21-32 人天

---

## 九、立即行动项（Today）

1. **轮换所有泄露的 API 密钥** — 最紧急
2. **修复 main.py 第 101-102 行缩进错误**
3. **将 `.env` 加入 `.gitignore` 并检查 git history**
