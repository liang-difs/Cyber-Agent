# Agent Context

> **每次 Agent 开工前必须阅读此文件。**

## 当前系统状态

### 当前阶段

### 版本
v0.9.0 | 314 后端测试全部通过 | 0 前端测试

### 已完成
- Phase 0-3 全部基础功能
- **P0 安全修复** — CORS 可配置化、PCAP 路径遍历防护、RBAC 实际生效（14 端点）、缺失依赖、ip_tool 缓存 bug、端口扫描误判 DNS 修复、IoC 查询修复
- **P1 CI/CD** — 全量 pytest CI（Python 3.11/3.12 + 覆盖率 + 前端 tsc + build）
- **P1 前端** — WebSocket 事件上限 500、ErrorBoundary、Redis 单例、角色菜单过滤、路由权限守卫
- **P1 部署** — 后端/前端 Dockerfile、nginx.conf、docker-compose 完整编排
- **P1 文档** — README.md（环境变量 + 安全检查清单 + LLM 切换 + 已知限制 + 版本状态）
- **PCAP 报告全链路优化** — 置信度修复、TLS 全局汇总、异常汇总节、4 级标签体系、ATT&CK 映射修正、IoC 白名单、恶意软件家族识别、应用协议上下文、HTML 导出
- **P0 仪表盘首页** — 态势总览（统计卡片 + 饼图 + 趋势图 + 最近告警/CVE + 服务健康）
- **P0 RAG Timeline** — rag_search 检索详情在 tool timeline 透出
- **P1 告警复核** — PATCH 状态更新 + 前端确认真阳性/标记误报/关闭
- **P1 PCAP 文件管理** — 历史上传文件列表 + 存储占用
- **P1 报告导出** — HTML 格式 + 浏览器打印为 PDF
- **P1 会话隔离** — 按 user_id 隔离，不同用户看到不同会话
- **P1 LLM 输出** — max_tokens 提升至 16384 + 截断自动续写
- **P2 资产管理** — Asset 模型 + CRUD API + 前端管理页面
- **P2 IoC 批量查询** — 批量查询端点 + 前端页面 + CSV 导出
- **P2 用户管理** — CRUD API + 前端页面 (admin only) + init_admin 脚本扩展
- **前端技术债清理** — 移除 ToolCallInfo、修复空赋值、提取共享颜色常量、ToolTimeline 默认 3 条
- **RBAC 修复** — require_permission 闭包 + auth=Depends 模式
- **299 个后端测试全部通过**
- **多智能体协同框架** — Coordinator + Planner + Analyzer + Responder + Executor，支持任务分解、并行执行、结果聚合
- **多智能体API** — /api/v1/multi-agent/* 端点，支持创建任务、查询Agent状态、列出能力
- **多智能体测试** — 15个测试用例，覆盖注册表、消息协议、协调者任务规划
- **工具可见性修复** — 19个工具全部在SYSTEM_PROMPT中列出，Agent可自动发现和调用
- **前端工具标签** — 19个工具的中文标签已补充完整
- **Sigma/YARA规则引擎** — SigmaEngine + YaraEngine + RuleManager，支持规则加载、匹配、统计
- **规则匹配工具** — rule_match工具，支持日志匹配(Sigma)、文件匹配(YARA)、数据匹配
- **知识图谱** — KnowledgeGraph + EntityExtractor，支持实体提取、关系构建、图查询
- **知识图谱工具** — knowledge_graph工具，支持搜索、查询、提取、路径查找
- **响应动作系统** — ActionManager + BlockIP/IsolateHost/Notify/QuarantineFile/DisableAccount
- **响应动作工具** — response_action工具，支持自动响应、单个动作执行、回滚

### 部分实现
- 资产管理 CMDB — 已建但未与告警研判联动
- 关联分析 — 基础已实现，多维度关联未扩展
- 报告生成 — Markdown + HTML，PDF/DOCX 未实现
- IoC 批量查询 — 单次已支持，定时自动检查未实现
- 多租户 RAG 隔离 — 代码有 tenant_id 作用域，Collection 级隔离未验证
- 知识图谱 — 基础框架已实现，实体提取和关系构建已支持，图谱数据待导入
- 响应动作 — 动作框架已实现，实际阻断/隔离API待集成

### 未开始
- RAG 完整知识库导入 (NVD 全量 + ATT&CK + Sigma)
- Prometheus + Grafana 监控面板
- MinIO 对象存储集成
- Celery 4 级优先队列分离
- 外部情报集成 (MISP/GreyNoise/Shodan/Spamhaus)
- PDF/DOCX 报告生成
- 前端 Playwright E2E 测试

### 当前禁止事项
- 禁止跳过脱敏管道
- 禁止硬编码 API Key
- 禁止跨租户 RAG 检索

### 当前核心目标

### 当前架构约束
- 所有 LLM 调用必须经过 `llm/router.py`
- 禁止 tools 直接调用模型
- 所有 Tool 必须遵循 `tool_protocol.md`
- 所有 Tool 必须通过 `tools/registry.py` 注册
- Agent 推理通过 `agent/react.py` ReAct 循环驱动
- 上下文压缩通过 `agent/context_compressor.py` 管理
- RBAC 权限通过 `rbac/permissions.py` 控制，通过 `require_permission()` 依赖注入到端点
- 审计日志通过 `middleware/audit.py` 自动记录
- Redis 客户端通过 `core/redis.py` 单例管理
- PCAP 路径必须在白名单目录内 (data/ + backend/data/ + /tmp)
- **新功能必须同步前端页面** — 后端实现+测试通过后，必须检查是否需要前端页面，如需要则一并完成设计和实现后再交付

### 当前技术债
- 前端零测试覆盖 (Playwright 已安装未配置)
- react.py run/run_streaming 约 80% 重复逻辑
- HTTP 明文敏感数据检测器未实现
- IP 信誉未接入 PCAP 告警置信度计算
- 前端 IoocCard/IpCard 的 parseNumericScore/getScoreColor 仍重复

### 当前阶段可执行任务
- 资产管理与告警研判联动
- P2 IoC 定期自动检查
- Stage 2.2 RAG 威胁情报导入
- 前端测试补充

## 开工检查清单

每次 Agent 启动时，按顺序阅读：

1. `AGENT_CONTEXT.md` — 当前阶段和约束
2. `PROJECT_STATE.json` — 机器可读状态
3. `runtime_governance.md` — 行为护栏（含 Phase 硬约束）
4. `coding_rules.md` — 编码约束
5. `known_issues.md` — 已知问题
6. `memory/` — 长期工程记忆

## 完工检查清单

每次 Agent 完成任务后：

1. 更新 `PROJECT_STATE.json`
2. 更新 `TECH_DEBT.md`（如有新增）
3. 更新 `known_issues.md`（如有发现）
4. 输出变更接口列表
5. 更新 `memory/` 相关条目（如有架构教训或失败尝试）
6. **检查前端页面同步** — 新功能是否需要前端页面？如需要，必须一并完成设计和实现
