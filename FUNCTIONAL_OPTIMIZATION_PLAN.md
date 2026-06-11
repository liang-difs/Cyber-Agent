# CyberSec Agent 功能模块深度优化计划

> 分析日期：2026-06-11 | 基于 4 大模块 150+ 项发现

---

## 一、核心发现汇总

| 模块 | P0 (关键) | P1 (高) | P2 (中) | 总计 |
|------|-----------|---------|---------|------|
| Agent 核心 | 3 | 5 | 4 | 12 |
| 工具层 (27个) | 4 | 10 | 8 | 22 |
| RAG/知识图谱/规则 | 4 | 6 | 5 | 15 |
| API/多智能体/分析/报告/响应 | 5 | 10 | 7 | 22 |
| **合计** | **16** | **31** | **24** | **71** |

---

## 二、P0 关键问题（必须修复）

### 2.1 Agent 核心

| # | 问题 | 位置 | 影响 |
|---|------|------|------|
| A1 | `run_streaming()` 缺失决策追踪 | `react.py:1046-1244` | 流式请求无审计记录，合规缺口 |
| A2 | SYSTEM_PROMPT 360行硬编码，每轮重复发送 | `react.py:48-360` | 每次对话浪费 ~6000 token，6轮浪费 ~36000 token |
| A3 | CJK token 估算严重不准 (`len//4`) | `context_compressor.py:16` | 中文内容被低估 2-4 倍，上下文压缩时机错误 |

### 2.2 工具层

| # | 问题 | 位置 | 影响 |
|---|------|------|------|
| T1 | SSL 验证禁用 (domain_tools, api_doc_parser) | `domain_tools.py:443`, `api_doc_parser.py:215` | 中间人攻击风险 |
| T2 | ip-api.com 使用 HTTP 明文 | `ip_tool.py:21` | GeoIP 数据可被篡改 |
| T3 | BlockIPAction 命令注入风险 | `actions.py:124` | `netsh` 命令未转义 IP 参数 |
| T4 | 二进制分析 PE 安全特性硬编码为 True | `binary_analysis.py:568-569` | NX/ASLR 检测结果虚假 |

### 2.3 RAG/知识图谱/规则

| # | 问题 | 位置 | 影响 |
|---|------|------|------|
| R1 | CVE 同步不更新 ChromaDB | `importer.py:220-275` | 向量搜索永久过时，只更新 BM25 |
| R2 | BM25 分词器破坏 CVE ID | `bm25_search.py:119` | "CVE-2024-1234" 变成 ["cve","2024","1234"]，精度极差 |
| R3 | Sigma 规则无时间窗口聚合 | `sigma_engine.py:237` | 暴力破解/扫描等阈值规则全部失效 |
| R4 | 知识图谱纯内存无持久化 | `graph.py:21-27` | 运行时学习的威胁情报重启即丢失 |

### 2.4 API/多智能体/响应

| # | 问题 | 位置 | 影响 |
|---|------|------|------|
| P1 | verify.py 端点无认证 | `verify.py` 全部 | 生产环境任何人都可调用 |
| P2 | 多智能体/事件/规则/响应端点无 RBAC | 多处 | 普通用户可执行响应动作 |
| P3 | audit.py `logger` 未定义 | `audit.py:78` | 运行时 NameError |
| P4 | 响应动作 rollback 是空壳 | `actions.py` 多处 | 声称回滚成功但实际未执行 |
| P5 | 协调器摘要字符串乱码 | `coordinator.py:932-935` | 用户可见的 mojibake |

---

## 三、P1 高优先级（强烈建议修复）

### 3.1 Agent 核心

| # | 问题 | 优化方案 |
|---|------|----------|
| A4 | `run()` 和 `run_streaming()` 重复 80% 逻辑 | 提取公共方法 `_execute_turn()` |
| A5 | 无工具执行超时 | 添加 `asyncio.wait_for(tool.execute(), timeout=30)` |
| A6 | 无并行工具调用 | 独立工具用 `asyncio.gather()` 并发执行 |
| A7 | planner.py 未集成到 ReAct 循环 | 在循环开始前自动调用 `detect_scenario()` |
| A8 | input_detector.py 未被调用 | 检测结果注入 SYSTEM_PROMPT 作为 hint |

### 3.2 工具层

| # | 问题 | 优化方案 |
|---|------|----------|
| T5 | hash_lookup VT+MB 顺序执行 | `asyncio.gather()` 并行 |
| T6 | dir_scan 每请求创建新 HTTP 客户端 | 共享连接池 |
| T7 | 无全局工具执行超时 | registry 层添加 60s 超时 |
| T8 | log_analysis 同步阻塞事件循环 | 移至 `asyncio.to_thread()` |
| T9 | cve_tool 无 NVD 429 重试 | 添加 retry-after 处理 |
| T10 | knowledge_graph 返回裸 dict 而非 ToolResult | 统一返回格式 |
| T11 | ioc_tool 批量模式无并发限制 | 添加 semaphore 限制 |
| T12 | vuln_scan 结果硬截断 50 条 | 按严重度排序后截断 |
| T13 | web_search Bing 爬虫脆弱 | 优先使用 SearXNG |
| T14 | response_action 无确认机制 | 破坏性动作需二次确认 |

### 3.3 RAG/知识图谱/规则

| # | 问题 | 优化方案 |
|---|------|----------|
| R5 | BM25 元数据在 RRF 融合时丢失 | 保留 BM25 原始 metadata |
| R6 | 知识图谱 `find_path` 只遍历出边 | 改为双向 BFS |
| R7 | 知识图谱 BFS 用 list 做队列 O(n) | 改用 `collections.deque` |
| R8 | Sigma 条件解析器不支持嵌套 | 实现完整条件求值器 |
| R9 | YARA offset 取第一个 match 的值 | 修复为当前 match 的 offset |
| R10 | 域名提取正则误报率高 | 添加 TLD 白名单过滤 |

### 3.4 API/多智能体

| # | 问题 | 优化方案 |
|---|------|----------|
| P6 | 无速率限制 | 添加 slowapi 中间件 |
| P7 | 5+ 端点缺少分页 | 统一 offset/cursor 分页 |
| P8 | dashboard 4 个 DB 查询顺序执行 | `asyncio.gather()` 并行 |
| P9 | 多智能体无单步超时 | 每步 120s 超时 |
| P10 | PlannerAgent 是死代码 | 集成或移除 |

---

## 四、落地计划

### Phase A: 关键 Bug 修复（1-2 天）

| 任务 | 文件 | 工作量 |
|------|------|--------|
| A-1 修复 audit.py logger 未定义 | `api/audit.py` | 0.5h |
| A-2 修复 coordinator.py 乱码字符串 | `multi_agent/coordinator.py` | 0.5h |
| A-3 verify.py 添加开发环境限制 | `api/verify.py` | 0.5h |
| A-4 CVE 端点 404 替代 200+error | `api/cve.py` | 0.5h |
| A-5 多智能体/事件/规则/响应添加 RBAC | 多个 api 文件 | 1h |

### Phase B: 安全加固（2-3 天）

| 任务 | 文件 | 工作量 |
|------|------|--------|
| B-1 domain_tools 启用 SSL 验证 | `tools/domain_tools.py` | 0.5h |
| B-2 api_doc_parser 启用 SSL 验证 | `tools/api_doc_parser_tool.py` | 0.5h |
| B-3 ip_tool 改用 HTTPS | `tools/ip_tool.py` | 0.5h |
| B-4 BlockIPAction 参数转义 | `response/actions.py` | 1h |
| B-5 响应动作添加二次确认 | `response/action_manager.py` | 1h |
| B-6 Rollback 方法真正实现 | `response/actions.py` | 2h |
| B-7 Pydantic 模型添加字段约束 | 多个 api 文件 | 2h |

### Phase C: Agent 核心优化（3-5 天）

| 任务 | 文件 | 工作量 |
|------|------|--------|
| C-1 run_streaming 添加决策追踪 | `agent/react.py` | 2h |
| C-2 提取 SYSTEM_PROMPT 到模板文件 | `agent/prompt.py` 新建 | 2h |
| C-3 工具描述从 registry 动态生成 | `agent/prompt.py` | 2h |
| C-4 CJK-aware token 估算 | `agent/context_compressor.py` | 1h |
| C-5 工具执行超时包装 | `tools/registry.py` | 1h |
| C-6 集成 input_detector 到 ReAct 循环 | `agent/react.py` | 2h |
| C-7 提取 run/run_streaming 公共方法 | `agent/react.py` | 3h |

### Phase D: 工具层优化（3-5 天）

| 任务 | 文件 | 工作量 |
|------|------|--------|
| D-1 hash_lookup 并行化 | `tools/hash_lookup_tool.py` | 1h |
| D-2 dir_scan 共享 HTTP 客户端 | `tools/dir_scan_tool.py` | 1h |
| D-3 log_analysis 异步化 | `tools/log_analysis_tool.py` | 1h |
| D-4 cve_tool NVD 429 重试 | `tools/cve_tool.py` | 1h |
| D-5 knowledge_graph 统一返回格式 | `tools/knowledge_graph_tool.py` | 1h |
| D-6 ioc_tool 批量并发限制 | `tools/ioc_tool.py` | 1h |
| D-7 vuln_scan 按严重度排序截断 | `tools/vuln_scan_tool.py` | 0.5h |
| D-8 二进制分析 PE 安全特性真实检测 | `tools/binary_analysis_tool.py` | 2h |
| D-9 RAG 工具添加错误处理 | `tools/rag_tool.py` | 0.5h |

### Phase E: RAG/知识图谱/规则修复（3-5 天）

| 任务 | 文件 | 工作量 |
|------|------|--------|
| E-1 CVE 同步同时更新 ChromaDB | `rag/importer.py` | 2h |
| E-2 BM25 分词器保留连字符 | `rag/bm25_search.py` | 1h |
| E-3 RRF 融合保留 BM25 元数据 | `rag/pipeline.py` | 1h |
| E-4 知识图谱 find_path 双向 BFS | `knowledge_graph/graph.py` | 2h |
| E-5 知识图谱 BFS 改用 deque | `knowledge_graph/graph.py` | 0.5h |
| E-6 Sigma 条件解析器完善 | `rules/sigma_engine.py` | 3h |
| E-7 YARA offset 修复 | `rules/yara_engine.py` | 0.5h |
| E-8 域名提取正则优化 | `knowledge_graph/extractor.py` | 1h |

### Phase F: API/多智能体改进（3-5 天）

| 任务 | 文件 | 工作量 |
|------|------|--------|
| F-1 添加 slowapi 速率限制 | `main.py` + 多个 api | 2h |
| F-2 统一分页模式 | 多个 api 文件 | 3h |
| F-3 dashboard 并行查询 | `api/dashboard.py` | 1h |
| F-4 多智能体单步超时 | `multi_agent/coordinator.py` | 1h |
| F-5 结果聚合语义增强 | `multi_agent/coordinator.py` | 3h |
| F-6 报告版本号动态化 | `reports/generator.py` | 0.5h |

---

## 五、优先级矩阵

```
紧急度 ↑
       │ Phase A    Phase B
  高   │ (Bug修复)  (安全加固)
       │───────────────────────
       │ Phase C    Phase D
  中   │ (Agent核心) (工具层)
       │───────────────────────
       │ Phase E    Phase F
  低   │ (RAG/KG)   (API/多智能体)
       │
       └──────────────────────→ 影响度
```

**建议执行顺序**: A → B → C → D → E → F

**预计总工作量**: 15-25 人天

---

## 六、预期收益

| 指标 | 当前 | 优化后 |
|------|------|--------|
| 流式请求审计覆盖率 | 0% | 100% |
| SYSTEM_PROMPT token 消耗/轮 | ~6000 | ~2000 (动态生成) |
| CVE ID 检索精度 | ~30% | ~90% |
| 工具执行超时保护 | 无 | 60s 全局超时 |
| API 速率限制 | 无 | 全端点覆盖 |
| 响应动作回滚可靠性 | 0% (空壳) | 100% |
| 知识图谱路径查找 | 仅出边 | 双向 BFS |
| Sigma 阈值规则可用性 | 0% | 100% |
