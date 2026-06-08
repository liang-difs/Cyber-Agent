# CyberSec Agent — 项目执行文档 v2.0

> 🛡 **机密 · 仅供内部使用**
>
> **网络安全智能分析平台**
>
> 面向 AI Agent 及工程团队 · 完整实施规范 · 优化增强版

| 字段 | 内容 |
|---|---|
| **编制日期** | 2026 年 5 月 |
| **版本** | v2.0（API 优先 + 本地备用） |
| **硬件规格** | 6× RTX 3090 (144GB VRAM) |
| **保密级别** | 内部机密 |
| **主力模型** | Claude API / GPT-4o（早期阶段） |
| **目标模型** | Qwen3-14B 本地部署（生产阶段） |

---

## 目录

1. [项目概述](#1-项目概述)
2. [系统架构](#2-系统架构)
3. [功能模块规格](#3-功能模块规格)
4. [RAG 知识库规格](#4-rag-知识库规格)
5. [API 接口规格](#5-api-接口规格)
6. [数据模型](#6-数据模型)
7. [部署规格](#7-部署规格)
8. [Agent 执行指南](#8-agent-执行指南)
9. [风险清单与缓解策略](#9-风险清单与缓解策略)
10. [最终验收标准](#10-最终验收标准)

---

## 1. 项目概述

### 1.1 项目背景与定位

CyberSec Agent 是一套前后端分离的网络安全智能分析平台，以大语言模型为推理核心，通过 ReAct 范式驱动多工具协同分析，实现网络流量解析、威胁情报关联、漏洞研判、告警分类和攻击溯源等核心安全场景的自动化闭环。

平台面向企业蓝队、MSSP 和 SOC 分析师，旨在将人均告警处理能力提升 3-5 倍，同时保持敏感数据的本地化合规要求。

### 1.2 模型部署策略（v2.0 核心调整）

本版本采用"API 优先、本地备用"的双轨策略。早期开发阶段使用 Claude API / GPT-4o API 快速验证 Agent 逻辑；待链路稳定后平滑迁移至本地 Qwen3-14B（服务器已具备 6× RTX 3090，144GB VRAM）。两套后端共用同一 OpenAI 兼容接口，切换只需修改 `base_url` 和 `model` 参数。

| 阶段 | 推理后端 | 适用条件 | 切换成本 |
|---|---|---|---|
| Phase A（当前） | Claude API (claude-opus-4) / GPT-4o | 开发验证、无 GPU 环境 | 0，直接使用 |
| Phase B | Qwen3-14B BF16（双卡 3090） | Tool Calling 稳定、数据合规要求 | 修改 `LLM_BASE_URL` + `LLM_MODEL` 环境变量 |
| Phase C（可选） | Qwen3-14B LoRA 微调版 | 工具调用格式错误率 > 15% | 50-120 A100-hour 微调，替换模型权重 |

### 1.3 核心功能矩阵

**原始五大功能模块**

- Pcap 流量包深度解析
- IoC 威胁情报查询（多源并发）
- CVE 漏洞库检索与 LLM 增强解读
- 告警规则自动研判（Sigma / YARA / Suricata）
- IP 地址多维威胁分析

**补全新增功能模块（共 7 项）**

- 攻击链溯源与 ATT&CK 战术映射（TTP 可视化）
- 资产管理与脆弱性评估（CMDB 集成）
- 多事件关联分析（时序图 + 图谱推理）
- 报告自动生成（PDF / DOCX 安全分析报告）
- Agent 任务审计与操作日志（可回溯）
- 用户权限管理与多租户隔离（RBAC）
- API 密钥管理与外部威胁源配置中心

### 1.4 设计原则

| 原则 | 说明 |
|---|---|
| **数据优先** | 所有 LLM 结论必须锚定工具返回数据，禁止无来源推断 |
| **工具可观测** | 每次工具调用的入参、出参、耗时全量记录到审计日志 |
| **接口兼容** | LLM 后端通过 OpenAI 兼容层抽象，API 与本地部署可热切换 |
| **防御性解析** | LLM 输出经宽容 JSON 解析层处理，格式抖动不导致任务失败 |
| **数据分域** | 敏感 pcap 数据脱敏后方可送入 LLM；多租户 RAG 严格隔离 |
| **渐进式交付** | 按阶段验收，每阶段产出可独立演示的最小可用功能 |

---

## 2. 系统架构

### 2.1 整体架构分层

| 层次 | 职责 | 关键技术 |
|---|---|---|
| 前端展示层 | 可视化分析界面、流式 LLM 输出、关系图谱 | React 18 + TypeScript · Ant Design Pro · ECharts · AntV G6 · WebSocket |
| API 网关层 | 统一鉴权、限流、路由分发 | FastAPI + Uvicorn · JWT · Nginx · CORS · Rate Limiting |
| **LLM 抽象层 ★新增** | OpenAI 兼容接口统一封装，屏蔽 API/本地差异 | LiteLLM Router · 熔断器 · 重试 · Token 计费统计 |
| Agent 推理层 | ReAct 推理循环、工具调度、会话记忆、上下文压缩 | LangChain / LlamaIndex · ConversationSummaryMemory · ContextWindowManager |
| 功能工具层 | 各安全分析工具的封装与执行 | Scapy · PyShark · yara-python · Sigma · 各威胁情报 API |
| 知识增强层 | RAG 检索、向量索引、混合搜索 | BGE-M3 · ChromaDB / Milvus · Elasticsearch BM25 · RRF 重排 |
| 数据持久层 | 任务、告警、资产、用户数据持久化 | PostgreSQL · Redis · MinIO · Elasticsearch |
| 基础设施层 | 服务编排、资源隔离、监控告警 | Docker Compose · Prometheus · Grafana · Loki |

### 2.2 LLM 抽象层设计（v2.0 新增核心模块）

LLM 抽象层是 v2.0 最重要的架构新增，使 API 与本地模型之间的切换对上层 Agent 完全透明。

#### 2.2.1 统一接口设计

- 所有模型调用通过 LiteLLM Router 统一代理
- 配置文件驱动：切换模型只需修改 `.env` 中 `LLM_PROVIDER` / `LLM_MODEL` / `LLM_BASE_URL`
- API 模式：`base_url=https://api.anthropic.com`，`model=claude-opus-4-5`
- 本地模式：`base_url=http://localhost:8001/v1`，`model=qwen3-14b`
- Token 计费统计：API 模式记录实际费用，本地模式记录 GPU 时间等效成本

#### 2.2.2 熔断与降级

- 熔断条件：连续 3 次调用失败或平均延迟 > 30s
- 降级策略：自动切换至备用 Provider（如从 Claude API 降级至 GPT-4o API）
- 恢复探测：熔断后每 60s 发送一次探测请求，成功则恢复
- 降级通知：前端显示「当前使用备用模型」黄色提示条

### 2.3 Agent 推理核心设计

#### 2.3.1 ReAct 推理循环

Agent 按照 **Thought → Action → Observation** 三步循环驱动，每轮最多执行一个工具调用，直到输出 `Final Answer:` 或达到最大轮次限制（默认 12 轮）。

#### 2.3.2 上下文窗口管理（v2.0 新增）

**解决的问题**：原始文档未设计上下文压缩策略。ReAct 12 轮循环 + 大体量 Observation（如 pcap 分析结果）会迅速消耗 LLM 上下文窗口，导致后期轮次截断或失忆。

- 使用 `ConversationSummaryMemory`：每 4 轮自动将历史 Thought/Observation 压缩为摘要
- Observation 截断策略：工具返回超过 2000 token 时，保留结构化字段摘要 + 原始数据引用 ID
- 上下文预算管理：每轮计算剩余 token 预算，不足时优先压缩最早的 Observation
- 阈值配置（env）：`CTX_COMPRESS_THRESHOLD=8000`，`CTX_OBS_MAX_TOKENS=2000`，`CTX_HISTORY_SUMMARY_INTERVAL=4`

#### 2.3.3 工具调用失败分类重试（v2.0 新增）

**解决的问题**：原始文档的"最多重试 3 次"策略不区分失败类型，会导致格式错误无限循环或网络超时浪费推理配额。

| 失败类型 | 重试策略 | 处理逻辑 |
|---|---|---|
| **网络超时 / 5xx** | 指数退避重试 3 次 | 等待 1s/2s/4s 后重试，第 4 次直接降级 |
| **LLM JSON 格式错误** | 修复 Prompt 重试 2 次 | 注入上一次错误样本，要求 LLM 修正格式 |
| **工具返回空结果** | 不重试 | 向 LLM 注入"未检出"指令，禁止推断 |
| **参数校验失败（Pydantic）** | 修复参数重试 1 次 | 将校验错误信息反馈给 LLM，要求重新提取参数 |
| **API 限流 429** | 等待窗口期后重试 | 解析 `Retry-After` 头，精确等待 |
| **工具内部异常** | 不重试，记录错误 | 返回结构化错误报告，LLM 据此调整策略 |

#### 2.3.4 LLM 输出宽容解析层（v2.0 新增）

**解决的问题**：原始文档直接依赖 Pydantic 校验 LLM JSON 输出，任何格式抖动都会导致整个任务失败。

解析优先级链（依次尝试，首次成功即返回）：

1. 直接 JSON 解析：`json.loads(output)`
2. 提取代码块：正则匹配 ` ```json ... ``` ` 后解析
3. 宽松提取：正则匹配最外层 `{ ... }` 花括号对
4. 修复尝试：去除中文注释、尾随逗号、单引号替换后再解析
5. 结构化 fallback：返回 `{ "error": "parse_failed", "raw": output }`，触发修复 Prompt 重试

#### 2.3.5 幻觉防控机制

- System Prompt 明确约束：所有确定性结论必须引用来源工具和数据字段
- 置信度强制标注：输出结构包含 `confidence`（0-1）和 `evidence_source` 字段
- 无数据保护语：工具返回空时，Prompt 要求 LLM 输出"未检出"而非编造结论
- 前端高亮：`confidence < 0.6` 的结论用橙色警告色显示，提示人工复核
- 输出后处理：正则检查 CVE 编号格式（`CVE-\d{4}-\d{4,7}`）、IP 地址合法性

### 2.4 微调策略决策矩阵

| 阶段 | 触发条件 | 方案 | 预期成本 |
|---|---|---|---|
| **Phase 0** | 项目启动 | Claude API + Prompt Engineering + RAG | 按 Token 计费，约 $50-200/月（开发阶段） |
| **Phase 1** | API 成本 > $500/月 或数据合规要求 | Qwen3-14B 本地部署（BF16，2× RTX 3090） | 0 边际成本，已有硬件 |
| **Phase 2** | 工具调用格式错误率 > 15% | LoRA 微调 Tool Calling，样本 3K-5K 条 | ~50 A100-hour（可用自有 6× 3090 替代） |
| **Phase 3** | 安全术语理解偏差 | LoRA 微调安全 QA，样本 8K-15K 条 | ~120 A100-hour |
| **Phase 4** | 输出格式极不稳定 | 全量 SFT（80G 显存）或继续 LoRA | ~400 A100-hour |

---

## 3. 功能模块规格

### 3.1 Pcap 流量包深度解析

#### 3.1.1 功能描述

接收用户上传的 `.pcap` / `.pcapng` 文件（硬限制 2GB），执行协议解析、流量还原、异常检测，输出结构化分析报告，并自动触发 IP 威胁分析和 IoC 查询的联动。

#### 3.1.2 脱敏管道（v2.0 新增）

**安全要求**：原始 pcap 包含明文 payload（密码、HTTP Body 等）。送入 LLM 前必须经过脱敏管道，防止敏感数据泄露至 API 或日志。

- 仅提取协议元数据：`src_ip`, `dst_ip`, `protocol`, `port`, `flags`, `packet_count`, `byte_count`
- payload 内容截断：最多保留前 64 字节，超出部分替换为 `[TRUNCATED]`
- IP 地址可配置脱敏：内网 IP 段可替换为 `10.x.x.x` 哈希化表示（企业合规模式）
- 脱敏后数据通过独立字段 `sanitized_for_llm: true` 标记，审计日志记录脱敏操作

#### 3.1.3 技术实现

- Celery 异步任务：文件上传后立即返回 `task_id`，分析在 Worker 中执行
- 流式读取：PyShark / Scapy 按帧流式处理，内存限制 512MB，超限自动分片
- 异常检测规则：端口扫描（>50 端口/分钟/源 IP）、SYN Flood、DNS 隧道、大流量突增
- 联动触发：提取所有外网 IP → 批量送入 IoC 查询工具（异步并发）

#### 3.1.4 输出格式

- `summary`：`{total_packets, duration_s, top_protocols[], top_talkers[]}`
- `anomalies[]`：`{type, severity, src_ip, dst_ip, detail, timestamp}`
- `ioc_candidates[]`：`{type, value, context}`
- `llm_analysis`：自然语言研判（必须引用 anomalies 字段，`confidence` + `evidence_source` 必填）

### 3.2 IoC 威胁情报查询

#### 3.2.1 数据源配置

| 数据源 | 查询对象 | 免费限额 | 缓存 TTL | 权重 |
|---|---|---|---|---|
| **VirusTotal** | IP / 域名 / URL / Hash | 4 次/分钟 | 1 小时 | 0.40 |
| **OTX AlienVault** | IP / 域名 / Hash / CVE | 无限（注册） | 30 分钟 | 0.30 |
| **AbuseIPDB** | IP | 1000 次/天 | 2 小时 | 0.15 |
| **MISP（自建）** | 全类型 | 无限（内网） | 15 分钟 | 0.30 |
| **微步 ThreatBook** | IP / 域名 / Hash | 商业 API | 1 小时 | 0.25 |

#### 3.2.2 关键实现要点

- `asyncio.gather` 并发查询所有已配置数据源，总超时 15s
- 各平台返回结果归一化为 `{source, score_0_100, tags[], raw_data}`
- 最终综合评分 = 加权平均（权重见上表，可在配置中心调整）
- 未配置 API Key 的数据源自动跳过，不报错，降级后评分重新归一化
- Redis 缓存 Key 格式：`ioc:{type}:{value_sha256}`

### 3.3 CVE 漏洞库检索

#### 3.3.1 本地化索引策略

NVD 全量数据（约 25 万条）本地化到 Elasticsearch，避免依赖外网、提升响应速度至 <50ms。

- 初始化：一次性拉取 NVD JSON Feeds 并建索引（约 2GB 数据）
- 增量同步：Celery Beat，每日 02:00，使用 NVD API 2.0 的 `lastModStartDate` 参数
- 混合检索：CVE 编号精确匹配（高优先级）+ 产品名称 + 描述全文检索 + BM25
- Embedding 版本追踪（v2.0 新增）：索引中记录 `embedding_model_version`，升级模型时自动触发全量重建

#### 3.3.2 LLM 增强解读

- 原始 NVD 英文描述 + RAG 检索相关 ATT&CK 技术 → LLM 输出中文影响分析
- 输出必须包含：危险等级评估、受影响版本、修复建议、是否有公开 PoC
- PoC 检测：查询 GitHub Search API，关键词 = CVE 编号，过滤 `stars > 5` 的仓库

### 3.4 告警规则研判

#### 3.4.1 智能研判流程

1. 规则命中 → 生成原始告警（`rule_id`、`matched_data`、`timestamp`）
2. 提取告警上下文：过去 24h 同源 IP 告警次数、目标资产等级（CMDB）、相关历史事件
3. ATT&CK 映射：根据 `rule_id` 查询预建映射表，确定 Tactic 和 Technique
4. LLM 研判：上下文 + ATT&CK 映射 + RAG → 真阳性概率、处置建议、关联告警 ID
5. 结果写入 PostgreSQL，`status` 字段：`pending` / `confirmed` / `false_positive`

#### 3.4.2 告警聚合与优先级队列（v2.0 新增）

**解决的问题**：原始文档未设计多租户/多分析师场景下的任务公平调度。大体量 pcap 任务会饿死高优先级告警研判任务。

| 优先级 | 队列名 | 任务类型 | 最大等待时间 |
|---|---|---|---|
| **P0 紧急** | celery_critical | IoC 查询、IP 威胁分析 | 30s，超时立即告警 |
| **P1 高** | celery_high | 告警研判、CVE 查询 | 2 分钟 |
| **P2 中** | celery_default | 多事件关联、攻击链溯源 | 10 分钟 |
| **P3 低** | celery_low | Pcap 分析、报告生成 | 无硬限制，监控积压 |

### 3.5 IP 地址威胁分析

#### 3.5.1 数据维度

- 地理位置：MaxMind GeoIP2 City 数据库，本地查询，每月更新
- ASN / 运营商：MaxMind ASN 数据库
- 基础设施类型：GreyNoise API（Tor 节点 / VPN / 扫描器 / CDN 区分）
- 历史恶意行为：AbuseIPDB（`reportCount`, `abuseConfidenceScore`）
- 开放端口 / Banner：Shodan API（每次查询消耗 1 Query Credit，做好 Redis 缓存）
- 黑名单：Spamhaus DROP / DNSBL 查询（通过 DNS 反查，免费）

#### 3.5.2 威胁评分模型

```
综合评分 = 0.30 × AbuseScore + 0.25 × BlacklistHits×20 + 0.20 × GreyNoiseScore + 0.15 × HistoryScore + 0.10 × GeoRiskScore
```

| 评分区间 | 风险等级 | 前端展示 |
|---|---|---|
| 0 - 30 | **低风险** | 绿色标签 |
| 31 - 60 | **中风险** | 黄色标签 |
| 61 - 80 | **高风险** | 橙色标签，建议关注 |
| 81 - 100 | **极高风险** | 红色标签，建议立即处置 |

### 3.6 攻击链溯源与 TTP 可视化（补全模块）

- 从多源事件（告警、流量、IoC）中自动提取攻击行为序列
- 映射到 MITRE ATT&CK 框架，输出 Tactic 时序图
- ATT&CK 全量数据（STIX 2.1 格式）本地化，导入 PostgreSQL JSON 列（可选 Neo4j）
- 规则到 TTP 的映射表：`Sigma rule_id → technique_id`，预建并随规则库更新
- LLM 辅助推理：多个离散 technique → 推断攻击意图和下一步预测
- 前端用 AntV G6 渲染有向图：节点 = 事件，边 = 时序关系

### 3.7 多事件关联分析（补全模块）

- 时间窗口内（可配置，默认 2h）同源 IP 或同目标 IP 的告警自动聚合
- 关联维度：`src_ip` / `dst_ip` / `user_agent` / JA3 指纹 / ASN / 恶意证书 SHA1
- LLM 对关联事件组做综合研判，识别"低危 + 低危 = 高危"的隐性攻击

### 3.8 报告自动生成（补全模块）

- 报告类型：单次事件分析报告 / 周期性威胁态势报告 / IOC 汇总报告
- 格式：PDF（WeasyPrint）/ DOCX（python-docx）/ Markdown
- 模板版本管理（v2.0 新增）：`tasks` 表记录 `report_template_version`，历史报告用生成时版本渲染
- 图表嵌入：pyecharts 服务端渲染生成静态图片后插入报告

---

## 4. RAG 知识库规格

### 4.1 知识库全量清单

| 知识库名称 | 内容来源 | 分块策略 | 向量维度 | 更新频率 | 租户隔离 |
|---|---|---|---|---|---|
| **CVE 知识库** | NVD JSON Feed / CNVD | 每条 CVE 一个 chunk | 1024 | 每日增量 | 共享（公开数据） |
| **ATT&CK 知识库** | MITRE ATT&CK STIX 2.1 | 每个 Technique 一个 chunk | 1024 | 季度更新 | 共享 |
| **Sigma 规则解释库** | Sigma 官方规则 + 注释 | 每条规则 + 说明 | 1024 | 按需 | 共享 |
| **威胁情报知识库** | MISP warninglists + APT 报告 | 语义段落切割（500 token） | 1024 | 月度 | 共享 |
| **内部事件历史库** | 历史分析报告、人工复核结论 | 每次分析一个 chunk | 1024 | 持续积累 | **★租户隔离** |
| **安全工具文档库** | Suricata / Zeek / YARA 文档 | 标题 + 段落切割 | 1024 | 版本更新 | 共享 |

### 4.2 多租户 RAG 隔离（v2.0 新增）

**解决的问题**：原始文档的 RBAC 覆盖了 PostgreSQL 层，但 ChromaDB/Milvus 的 Collection 未设计租户隔离，存在跨租户历史数据泄露风险。

- 公共知识库（CVE / ATT&CK / Sigma 等）：所有租户共享同一 Collection，前缀 `kb_public_`
- 租户私有库（内部事件历史）：每个租户独立 Collection，命名格式 `kb_tenant_{tenant_id}_events`
- 检索时：先查公共 Collection，再查当前租户私有 Collection，结果合并后 RRF 重排
- BGE-M3 Embedding 服务版本追踪：Collection metadata 记录 `embedding_version`，升级时触发异步重建任务

### 4.3 混合检索与重排序

- 查询向量化：用户问题 → BGE-M3 Embedding（本地推理，不走外部 API）
- 向量检索：Milvus / ChromaDB Top-K = 8，余弦相似度
- BM25 全文检索：Elasticsearch 关键词匹配（对 CVE 编号、IP 地址等精确词至关重要）
- RRF 融合：`score = Σ 1/(k+rank_i)`，`k=60`
- Reranker 重排序（可选）：BGE-Reranker-v2-m3 对 Top-8 精排，取 Top-4 注入 Prompt
- BGE-M3 降级保护（v2.0）：Embedding 服务不可用时，自动降级为纯 BM25 检索，不中断 RAG 链路

### 4.4 RAG Prompt 模板

系统 Prompt 核心结构（所有工具共用）：

```
你是一名网络安全专家。
以下是检索到的相关背景知识：
{retrieved_context}

工具返回的分析数据：
{tool_results}

规则：若背景知识与工具数据有矛盾，以工具数据为准。若信息不足，明确说明"无法确定"而非推测。
问题：{user_query}
```

---

## 5. API 接口规格

### 5.1 接口清单

| Method | 路径 | 描述 | 响应类型 | 优先级队列 |
|---|---|---|---|---|
| **POST** | `/api/v1/auth/login` | 用户登录，返回 JWT | JSON | - |
| **POST** | `/api/v1/pcap/upload` | 上传 pcap 文件，返回 task_id | JSON | P3 |
| **GET** | `/api/v1/tasks/{id}` | 查询异步任务状态与结果 | JSON | - |
| **WS** | `/api/v1/agent/chat` | Agent 多轮对话，流式输出 | WS Stream | - |
| **POST** | `/api/v1/ioc/lookup` | 批量 IoC 查询（混合类型） | JSON | P0 |
| **GET** | `/api/v1/cve/{cve_id}` | CVE 详情 + LLM 解读 | JSON | P1 |
| **POST** | `/api/v1/alert/evaluate` | 告警规则研判 | JSON | P1 |
| **POST** | `/api/v1/ip/analyze` | IP 威胁分析 | JSON | P0 |
| **GET** | `/api/v1/events/correlate` | 多事件关联分析 | JSON | P2 |
| **GET** | `/api/v1/attack-chain/{event_id}` | 攻击链溯源 + ATT&CK 映射 | JSON | P2 |
| **POST** | `/api/v1/reports/generate` | 生成分析报告（异步） | JSON | P3 |
| **GET** | `/api/v1/assets` | 资产列表查询（CMDB） | JSON | - |
| **GET** | `/api/v1/admin/audit-logs` | 操作审计日志（管理员） | JSON | - |
| **GET** | `/api/v1/llm/status` | LLM 后端状态（API/本地/熔断） | JSON | - |

### 5.2 统一响应格式

- **成功**：`{"code": 200, "data": {...}, "request_id": "uuid"}`
- **异步任务**：`{"code": 202, "task_id": "...", "status_url": "/api/v1/tasks/{id}"}`
- **失败**：`{"code": 4xx/5xx, "error": "message", "detail": "...", "request_id": "uuid"}`
- 所有接口响应头必须包含 `X-Request-Id`，便于日志追踪

### 5.3 WebSocket 流式协议

- **连接**：携带 `Authorization: Bearer {jwt}` 作为查询参数
- **客户端发送**：`{"type": "chat", "content": "用户消息", "session_id": "..."}`
- **Token 块**：`{"type": "token", "content": "..."}`
- **工具调用通知**：`{"type": "tool_call", "tool": "pcap_analyze_tool", "status": "running"}`
- **LLM 后端状态（v2.0）**：`{"type": "llm_backend", "provider": "claude_api", "model": "claude-opus-4-5"}`
- **完成**：`{"type": "done", "total_tokens": 1234, "cost_usd": 0.0023}`
- **错误**：`{"type": "error", "code": "...", "message": "..."}`

---

## 6. 数据模型

### 6.1 核心数据表（PostgreSQL）

| 表名 | 关键字段 | 说明 |
|---|---|---|
| `users` | id, username, email, role, tenant_id, created_at | 用户账户，支持多租户，RBAC 角色 |
| `tasks` | id, type, priority, status, queue_name, input_ref, result, cost_usd, created_by, created_at | 异步任务跟踪，含优先级与费用记录 |
| `alerts` | id, rule_id, src_ip, dst_ip, severity, status, verdict, confidence, ttp_ids[], created_at | 告警记录，含 ATT&CK 映射 |
| `ioc_cache` | id, type, value_hash, results_json, queried_at, expires_at | IoC 查询 Redis 缓存的持久化备份 |
| `events` | id, type, tenant_id, related_alert_ids[], related_ip_ids[], timeline_json, created_at | 关联事件，含租户隔离 |
| `assets` | id, ip, hostname, os, criticality, owner, tags[], last_seen | 资产 CMDB |
| `audit_logs` | id, user_id, action, resource, detail_json, ip, created_at | 操作审计，所有写操作必须记录 |
| `api_keys` | id, user_id, name, key_hash, scopes[], last_used, expires_at | 外部 API Key 管理，只存 SHA-256 哈希 |
| `reports` | id, task_id, type, format, template_version, file_path, created_at | 报告元数据，含模板版本 ★新增 |
| `llm_usage` | id, user_id, provider, model, prompt_tokens, completion_tokens, cost_usd, created_at | LLM 调用计费统计 ★新增 |

### 6.2 关键索引规划

- `alerts` 表：`idx_alerts_src_ip_created`（src_ip, created_at DESC）— 告警聚合查询
- `alerts` 表：`idx_alerts_tenant_status`（tenant_id, status）— 多租户待处理告警
- `ioc_cache` 表：`idx_ioc_cache_value_hash`（value_hash, expires_at）— 缓存命中
- `audit_logs` 表：`idx_audit_logs_user_created`（user_id, created_at DESC）— 用户操作查询
- `llm_usage` 表：`idx_llm_usage_user_date`（user_id, DATE(created_at)）— 按日统计费用

---

## 7. 部署规格

### 7.1 Docker Compose 服务清单

| 服务名 | 镜像基础 | 资源配置 | 端口 |
|---|---|---|---|
| frontend | nginx:alpine + React build | 0.5 CPU / 256MB | 80 |
| api | python:3.11-slim | 2 CPU / 4GB RAM | 8000 |
| worker_high | python:3.11-slim | 4 CPU / 8GB RAM | 内部 (P0/P1) |
| worker_low | python:3.11-slim (+tshark) | 4 CPU / 16GB RAM | 内部 (P2/P3) |
| llm (API) | — (调用外部 API) | 无 GPU 需求 | — |
| llm (本地) | vllm/vllm-openai (GPU) | 2×GPU / 48GB VRAM (BF16) | 8001 |
| embedding | python:3.11 + BGE-M3 | 2 CPU / 6GB RAM | 8002 |
| redis | redis:7-alpine | 0.5 CPU / 1GB | 6379 |
| postgres | postgres:16-alpine | 1 CPU / 2GB | 5432 |
| elasticsearch | elasticsearch:8.x | 2 CPU / 4GB | 9200 |
| minio | minio/minio | 1 CPU / 2GB | 9000 |
| chromadb | chromadb/chroma | 1 CPU / 2GB | 8003 |
| prometheus | prom/prometheus | 0.5 CPU / 512MB | 9090 |
| grafana | grafana/grafana | 0.5 CPU / 512MB | 3000 |

### 7.2 GPU 显存规划（6× RTX 3090 配置）

当前服务器配置 6× RTX 3090（144GB 总 VRAM），Phase B 迁移本地模型时无需额外采购，双卡运行 Qwen3-14B BF16 后仍余 4 张显卡可用于 Embedding 服务或并发 LoRA 微调。

| 配置方案 | 显卡分配 | Qwen3-14B 精度 | 推理速度 | 适用场景 |
|---|---|---|---|---|
| **★ 推荐** | GPU 0-1（48GB） | BF16 全精度 | ~40 tok/s | Phase B 生产环境 |
| 经济 | GPU 0（24GB） | INT8 量化 (AWQ) | ~30 tok/s | 中小团队 / 开发测试 |
| 受限 | GPU 0（24GB） | INT4 量化 (GPTQ) | ~20 tok/s | 快速验证 |
| 高并发 | GPU 0-3（96GB） | BF16，多副本 | ~80 tok/s | 压测 / 峰值场景 |
| 余量用途 | GPU 2-5 | BGE-M3 + 微调任务 | - | Embedding + LoRA 并行 |

### 7.3 环境变量配置（.env）

所有模型切换通过环境变量完成，无需修改代码：

```bash
# Phase A — API 模式
LLM_PROVIDER=openai
LLM_BASE_URL=https://api.anthropic.com
LLM_MODEL=claude-opus-4-5
LLM_API_KEY=sk-ant-...

# Phase B — 本地模式（切换只需改这 3 行）
LLM_PROVIDER=openai
LLM_BASE_URL=http://localhost:8001/v1
LLM_MODEL=qwen3-14b
LLM_API_KEY=EMPTY

# 上下文管理
CTX_COMPRESS_THRESHOLD=8000
CTX_OBS_MAX_TOKENS=2000
CTX_HISTORY_SUMMARY_INTERVAL=4

# vLLM 性能优化（本地模式）
VLLM_ENABLE_PREFIX_CACHING=true
VLLM_MAX_MODEL_LEN=32768
```

### 7.4 最低硬件要求

| 组件 | Phase A（API 模式） | Phase B（本地模式） |
|---|---|---|
| **CPU** | 8 核 16 线程 | 8 核 16 线程 |
| **RAM** | 32GB（无 LLM 本地推理） | 64GB（Qwen3 + ElasticSearch + Worker） |
| **存储** | SSD 500GB | SSD 1TB（NVD 索引 ~80GB + 模型权重 ~30GB） |
| **GPU** | 无需求 | ≥2× RTX 3090（现有 6 张，无需采购） |
| **网络** | 外网访问 Claude API / OpenAI API | 内网即可，API Key 仅开发调试用 |

### 7.5 监控告警配置

- Prometheus 采集：FastAPI `/metrics` 端点、vLLM `/metrics`（本地模式）、Celery exporter
- Grafana 看板：API P95 延迟、LLM token/s 吞吐、Celery 队列积压（分优先级）、API 费用趋势（v2.0）
- 日志：Loki 收集所有容器标准输出，Grafana 联合查询
- 告警规则：任务失败率 >5% → 邮件；LLM 队列积压 >20 → Slack；API 日费用 >$50 → 邮件（v2.0）
- LLM 熔断状态：`/api/v1/llm/status` 端点，Grafana 显示当前后端和熔断状态

---

## 8. Agent 执行指南

本节专为 AI Agent 编写，描述实施顺序、验收标准和关键约束。各阶段存在依赖关系，不可并行启动，每阶段完成验收后方可进入下一阶段。

### 8.1 实施阶段总览

| 阶段 | 名称 | 预计时长 | 核心产出 |
|---|---|---|---|
| **阶段 0** | 基础设施初始化 | 1-2 天 | 所有基础服务启动，Claude API 可调通 |
| **阶段 1** | Agent 核心框架 | 2-3 天 | ReAct Agent + 流式 WebSocket + 上下文管理 |
| **阶段 2** | 基础功能模块 | 5-7 天 | CVE / IoC / IP 查询工具 + RAG 检索 |
| **阶段 3** | 重型模块 | 5-7 天 | Pcap 分析 + 告警研判 + 优先级队列 |
| **阶段 4** | 高级功能 | 3-5 天 | 攻击链溯源 + 关联分析 + 报告生成 + RBAC |
| **阶段 5** | 优化与本地化 | 3-5 天 | 全量 RAG 导入 + 切换本地模型 + 压测 |

### 8.2 阶段详细规格

#### 阶段 0：基础设施初始化（1-2 天）

- 克隆项目模板，初始化 monorepo 结构（backend / frontend / infra / docs）
- 编写 `docker-compose.yml`，启动 Redis / PostgreSQL / MinIO / Elasticsearch
- 运行数据库迁移脚本，创建核心数据表（见第 6 节）
- 配置 `.env`，设置 Claude API Key（Phase A 模式），验证 LiteLLM Router 可正常调通 Claude API
- 下载 BGE-M3 模型，启动 Embedding 服务，验证向量维度为 1024

**阶段 0 验收**：`curl` 可访问所有服务端口，LiteLLM 代理调用 Claude API 返回正确响应，Embedding 服务返回 1024 维向量

#### 阶段 1：Agent 核心框架（2-3 天）

- 实现 FastAPI 主应用骨架，配置 JWT 认证中间件
- 集成 LangChain + LiteLLM Router，实现 ReAct Agent（通过 `LLM_BASE_URL` 抽象层连接）
- 实现 WebSocket 流式输出端点（`/api/v1/agent/chat`），含 LLM 后端状态推送
- 实现工具注册中心（Tool Registry）+ Echo 测试工具，验证完整 Tool Calling 链路
- 实现上下文压缩管理器（ConversationSummaryMemory + Observation 截断）
- 实现 LLM 输出宽容解析层（5 级 fallback 链）
- 实现 Redis 会话记忆，验证多轮对话上下文保持

**阶段 1 验收**：通过 WebSocket 客户端完成 5 轮对话；第 5 轮时上下文已触发压缩但对话仍连贯；LLM 故意输出 Markdown 包裹 JSON 时宽容解析层能正确提取

#### 阶段 2：基础功能模块（5-7 天）

- 实现 CVE 查询工具（最简单，纯 API 查询，快速验证完整链路）
- 实现 IoC 查询工具（接入 OTX 免费 API，验证并发查询和 Redis 缓存）
- 实现 IP 威胁分析工具（本地 GeoIP 库 + AbuseIPDB）
- 实现 ChromaDB 向量存储，导入 1000 条 CVE 数据，验证 RAG 检索 + RRF 重排序
- 实现 BGE-M3 降级保护（Embedding 服务不可用时降级为纯 BM25）
- 前端：聊天界面 + 工具调用进度展示 + CVE 搜索页 + LLM 后端状态指示器

**阶段 2 验收**：自然语言问"CVE-2024-3400 影响什么"，Agent 查询工具 + RAG 后输出中文解读，`evidence_source` 字段有值；停止 Embedding 服务后查询降级为 BM25 但仍返回结果

#### 阶段 3：重型模块（5-7 天）

- 实现 4 级优先级 Celery 队列（`celery_critical` / `high` / `default` / `low`）
- 实现 MinIO 文件存储 + 异步任务体系
- 实现 Pcap 分析工具（含文件分片上传、流式读取、脱敏管道、异常检测）
- 实现 YARA 规则引擎集成，实现 Sigma 规则转 ES 查询
- 实现告警研判工具（含 ATT&CK 映射、上下文注入、聚合去重）
- 验证优先级公平调度：同时提交大 pcap 任务和 IP 查询任务，IP 查询应优先完成

**阶段 3 验收**：上传含端口扫描特征的 pcap 文件，系统识别扫描行为、提取可疑 IP、触发告警研判、脱敏管道正确执行（`audit_log` 有 `sanitized_for_llm: true` 记录）

#### 阶段 4：高级功能（3-5 天）

- 实现多事件关联分析引擎（时间窗口 + 多维度关联）
- 实现攻击链溯源和 ATT&CK TTP 可视化（AntV G6）
- 实现报告自动生成（PDF + DOCX），含模板版本管理
- 实现 RBAC 权限体系和多租户隔离（含 RAG Collection 隔离）
- 实现操作审计日志（所有 POST/PUT/DELETE 接口全量记录）
- 配置 Prometheus + Grafana 监控（含 LLM 费用面板）

**阶段 4 验收**：完整演示：上传 pcap → 触发多告警 → 关联分析 → ATT&CK 映射 → 生成 PDF 报告；两个不同租户的历史事件不互相可见

#### 阶段 5：优化与本地化（3-5 天）

- 全量 RAG 知识库数据导入（NVD 全量 CVE + ATT&CK + Sigma 规则库）
- Elasticsearch CVE 本地索引初始化（约 80GB）
- 【关键】切换本地模型：修改 `.env` 中 `LLM_BASE_URL` + `LLM_MODEL`，启动 vLLM（2× RTX 3090 BF16）
- 运行回归测试集（固定样本 pcap + 预期输出对比），验证本地模型与 API 模式结果一致性
- 性能调优：vLLM `prefix_caching=true`、Celery 并发数、ES 索引分片
- 安全加固：输入校验、文件类型校验、SQL 注入防护、Rate Limiting

**阶段 5 验收**：压测：10 并发用户，API P95 < 500ms（不含 LLM 推理）；本地 LLM 首 Token < 3s；回归测试通过率 > 95%

### 8.3 关键约束（Agent 必须遵守）

> ⚠️ **禁止**：在未完成当前阶段验收的情况下进入下一阶段。验收标准是最低要求，不是可选项。

- 禁止在工具调用链路中跳过脱敏管道，即使是测试 pcap 文件
- 禁止将 API Key 硬编码到代码中，必须通过 `.env` 配置
- 禁止创建跨租户的 RAG 检索调用，内部事件历史库必须严格按 `tenant_id` 隔离
- 禁止在 Phase A 向 Claude API 发送真实客户的 pcap 原始 payload

### 8.4 目录结构规范

```
cybersec-agent/
├── backend/
│   ├── app/
│   │   ├── api/          # 路由层
│   │   ├── agent/        # ReAct Agent + LLM 抽象层 + 上下文管理
│   │   ├── tools/        # 安全工具封装
│   │   ├── rag/          # RAG 检索 + 多租户 Collection 管理
│   │   ├── llm/          # LiteLLM Router + 熔断 + 解析层 ★新增
│   │   ├── sanitizer/    # pcap 脱敏管道 ★新增
│   │   ├── models/       # SQLAlchemy 数据模型
│   │   ├── services/     # 业务逻辑层
│   │   ├── tasks/        # Celery 任务（4 优先级队列）★新增
│   │   └── core/         # 配置、安全、依赖注入
├── frontend/
│   └── src/
│       ├── pages/
│       ├── components/
│       ├── services/     # API 调用层
│       └── stores/       # 状态管理
├── infra/
│   ├── docker-compose.yml
│   ├── docker-compose.local-llm.yml  # 本地 LLM override ★新增
│   ├── prometheus/
│   └── nginx/
├── scripts/              # 数据初始化脚本
├── tests/
│   ├── regression/       # 固定样本回归测试集 ★新增
│   └── fixtures/         # 测试用 pcap + 预期输出 ★新增
└── docs/
```

---

## 9. 风险清单与缓解策略

| 风险项 | 级别 | 缓解策略 |
|---|---|---|
| LLM 幻觉（编造 CVE / IoC 结论） | **高** | 强制锚定工具数据；输出包含 `evidence_source`；前端低置信度标红 |
| LLM 上下文溢出（ReAct 长循环） | **高** | ★v2.0 新增：ConversationSummaryMemory + Observation 截断 + Token 预算管理 |
| LLM JSON 格式解析失败 | **高** | ★v2.0 新增：5 级宽容解析层 + 分类重试，格式错误不再导致任务整体失败 |
| Tool Calling 格式不稳定（本地模型） | **高** | API 阶段积累失败样本；Phase C 进行 LoRA 微调；Pydantic 校验 + 修复重试 |
| pcap 大文件 OOM | **高** | 流式读取 + 内存限制 512MB + Celery P3 队列 + 文件大小硬限制 2GB |
| 敏感 pcap 数据泄露至 LLM | **高** | ★v2.0 新增：脱敏管道强制执行；仅提取元数据；audit_log 记录脱敏操作 |
| Celery 任务饿死（低优先级阻塞高优先级） | **高** | ★v2.0 新增：4 级优先级队列；P0/P1 独立 Worker；P3 任务最大 Worker 数限制 |
| 多租户 RAG 数据泄露 | **高** | ★v2.0 新增：租户私有 Collection 隔离；检索时强制注入 tenant_id 过滤 |
| Claude API 费用失控 | **中** | ★v2.0 新增：日费用告警（>$50）；llm_usage 表计费统计；Token 预算硬限制 |
| Claude API 熔断 / 不可用 | **中** | ★v2.0 新增：LiteLLM 熔断器 + 自动切换备用 Provider；前端状态提示 |
| BGE-M3 Embedding 服务单点故障 | **中** | ★v2.0 新增：自动降级为纯 BM25 检索；服务恢复后自动切回 |
| Embedding 模型升级数据漂移 | **中** | ★v2.0 新增：Collection 记录 `embedding_version`；升级时触发异步全量重建任务 |
| 外部威胁情报 API 限流 / 断网 | **中** | Redis 缓存 + 降级响应 + 本地 MISP 兜底；评分归一化处理 |
| GPU 显存不足（本地模式） | **中** | 量化部署（INT8/INT4）+ vLLM `max_model_len` 限制；当前硬件充裕暂不适用 |
| ES 索引磁盘空间耗尽 | **低** | 独立 volume + 磁盘使用率告警（>80%）+ 旧 pcap 数据清理策略 |
| 报告历史版本渲染错误 | **低** | ★v2.0 新增：`reports` 表记录 `template_version`；历史报告用生成时模板版本渲染 |

---

## 10. 最终验收标准

### 10.1 功能验收

| 验收场景 | 输入 | 预期输出 | 通过标准 |
|---|---|---|---|
| **CVE 查询** | CVE-2024-3400 | 漏洞详情 + CVSS 评分 + 中文影响分析 + 修复建议 | < 5s，confidence > 0.8，无幻觉 |
| **IoC 批量查询** | 3 个混合类型 IoC | 各平台评分 + 综合威胁评分 + 标签 | < 15s，来源标注完整 |
| **IP 威胁分析** | 已知恶意 IP | 地理位置 + 威胁评分 > 60 + 黑名单命中 | 评分误差 < 10 |
| **Pcap 分析** | 含端口扫描的 50MB pcap | 识别扫描行为 + 提取可疑 IP + 脱敏执行 | < 120s，audit_log 有脱敏记录 |
| **告警研判** | Sigma 规则命中告警 | 真阳/误报 + ATT&CK Tactic + 处置建议 | confidence 字段有值 |
| **攻击链溯源** | 5 个关联告警 ID | TTP 序列 + MITRE Tactic 时序图 | Tactic 顺序合理 |
| **报告生成** | 完整分析事件 | PDF 报告含摘要 + 时序 + 建议 | 可下载，template_version 有值 |
| **多轮对话** | 5 轮追问同一事件 | 上下文连贯，第 5 轮触发压缩但不失忆 | 无上下文丢失 |
| **上下文压缩** | 构造 12 轮 ReAct | 最终轮次仍引用第 1 轮工具数据 | 数据不被截断遗忘 |
| **LLM 切换** | 改 .env 后重启 | Agent 无缝使用新后端 | 前端 LLM 状态指示器正确更新 |
| **多租户隔离** | 租户 A 查租户 B 历史 | RAG 检索返回空结果 | 严格隔离，无跨租户数据 |
| **熔断降级** | 关闭主 LLM 后端 | 自动切换备用 Provider，前端显示黄色提示 | 服务不中断 |

### 10.2 性能验收

| 指标 | Phase A（API 模式） | Phase B（本地 BF16） |
|---|---|---|
| API 响应（不含 LLM 推理）P95 | < 500ms | < 500ms |
| LLM 首 Token 延迟 | < 2s（Claude API） | < 3s（本地 BF16） |
| LLM 流式输出速率 | > 30 tok/s | > 15 tok/s |
| Pcap 分析（50MB 文件） | < 120s | < 120s |
| CVE 本地索引查询 | < 50ms | < 50ms |
| IoC 并发查询（3 平台） | < 15s | < 15s |
| 系统可用性 | > 99% | > 99% |
| P0 队列任务最大等待 | < 30s | < 30s |

### 10.3 安全验收

- 所有 API 端点鉴权覆盖率 100%（`/health` 除外）
- 上传文件类型验证：拒绝非 pcap/pcapng 后缀文件，magic bytes 二次校验
- API Key 存储：数据库中只存 SHA-256 哈希，明文不落库
- SQL 注入测试：OWASP Top 10 注入场景全部通过
- 所有写操作（POST/PUT/DELETE）在 `audit_logs` 表有记录
- 跨租户 RAG 隔离测试：租户 A 的 embedding 查询不返回租户 B 的内容
- 脱敏管道测试：含真实密码的 pcap 文件，LLM 收到的 Observation 中无明文密码

> ⚠️ **Phase A 特别注意**：在使用 Claude API 阶段，必须通过脱敏管道验收测试后，方可处理任何真实客户数据。禁止在验收前将包含真实业务 payload 的 pcap 文件上传到系统。

### 10.4 回归测试基准（v2.0 新增）

建立固定样本测试集，每次切换 LLM 后端（API ↔ 本地）或升级依赖后自动运行，确保功能一致性。

- 测试集位置：`tests/regression/` + `tests/fixtures/`
- 测试用例：至少包含 CVE 查询 × 5、IoC 查询 × 5、IP 分析 × 3、Pcap 分析 × 2（固定样本文件）
- 评估方式：对比结构化字段（CVE 编号、威胁评分区间、ATT&CK Tactic 分类），不对比自然语言措辞
- 通过标准：结构化字段一致率 > 95%；confidence 字段差异 < 0.15
- CI 集成：阶段 5 完成后配置 GitHub Actions，每次 main 分支合并自动运行回归测试

---

*— 文档结束 —*

> CyberSec Agent v2.0 · 项目执行文档 · 机密 · 2026 年 5 月
>
> © 2026 CyberSec Agent Team
