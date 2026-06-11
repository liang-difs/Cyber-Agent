"""ReAct Agent — Thought → Action → Observation loop.

Orchestrates LLM reasoning with tool execution.
No LangChain dependency — uses LLM Router and Tool Registry directly.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, AsyncIterator
from dataclasses import dataclass, field

from app.agent.json_parser import parse_llm_json
from app.agent.planner import generate_plan, build_plan_prompt, ExecutionPlan
from app.agent.context_compressor import (
    compact_tool_observation,
    should_compress,
    compress_history,
)
from app.agent.decision_trace import decision_tracker

logger = logging.getLogger(__name__)


@dataclass
class ReActResult:
    """Result of a ReAct agent run."""
    success: bool
    final_answer: str
    turns_used: int
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    total_tokens: int = 0
    total_latency_ms: int = 0


@dataclass
class TurnEvent:
    """Event emitted during a ReAct turn."""
    type: str  # "thought" | "tool_call" | "tool_result" | "answer_token" | "usage" | "error"
    turn: int
    content: Any


SYSTEM_PROMPT = """你是 CyberSec Agent，一个具备自主决策能力的通用网络安全智能体。

你拥有以下工具：
- pcap_analysis: 分析 pcap/pcapng 网络流量文件（输入 pcap_path）。返回流记录、DNS、协议、异常检测。分析完成后异常自动写入告警系统。返回的 external_ips_for_lookup 和 domains_for_lookup 可串联 ip_threat_analysis 和 ioc_lookup。
- cve_lookup: 查询 CVE 漏洞详情（输入 cve_id，如 CVE-2024-1234）。优先从知识库检索，查不到时实时查询 NVD API。
- cve_catalog: 按年份、CVSS、KEV、严重等级或关键字筛选并列出 CVE / KEV 记录，适合批量列表、统计和交集查询。
- ioc_lookup: 查询 IoC 威胁情报（输入 value，自动检测 IP/域名/Hash/URL）。支持批量查询：value 中用逗号分隔多个 IoC（如 "1.2.3.4,evil.com,abc123"），一次调用返回所有结果
- ip_threat_analysis: 分析 IP 地址威胁（输入 ip）
- rag_search: 从知识库检索相关安全信息（输入 query）
- web_search: 联网搜索互联网信息（输入 query）。当知识库和专业工具无法回答时使用。
- nmap_scan: 网络端口扫描和服务版本检测（输入 target，可选 scan_type/ports）。渗透测试信息收集必备。
- vuln_scan: 使用 nuclei 进行自动化漏洞扫描（输入 target URL/IP）。返回 CVE 漏洞列表和严重等级。
- dir_scan: Web 目录和文件枚举扫描（输入 target URL）。发现隐藏路径、备份文件、配置文件暴露。
- log_analysis: 分析安全日志（输入 log_content）。自动提取 IoC（IP/域名/Hash/URL）、检测攻击模式（暴力破解、注入、提权、横向移动等）。
- hash_lookup: 查询文件哈希威胁情报（输入 hash_value）。支持 VirusTotal 和 MalwareBazaar，自动检测哈希类型。
- encoding_tool: 文本编解码工具（输入 text + operation）。支持 base64、hex、URL、HTML entity、ROT13、Morse、二进制编解码和自动检测。CTF/逆向常用。
- echo: 回显测试工具（输入 message）
- archive: 分析压缩文件（输入 file_path）。支持 ZIP/RAR/7Z/TAR/GZIP/BZIP2 格式，自动解压、文件类型识别、内容枚举。可串联 hash_lookup 分析压缩包内的可疑文件。
- api_doc_parser: 解析 API 接口文档（输入 file_path 或 url）。支持 Swagger 2.0/OpenAPI 3.x/Postman Collection，提取所有端点、HTTP 方法、参数、认证方式。可串联 vuln_scan 对发现的端点进行漏洞扫描。
- config_parser: 解析配置文件（输入 file_path）。支持 JSON/YAML/XML/CSV/ENV/INI 格式，自动识别敏感信息（密码、密钥、Token）、安全配置审计。可用于代码审计和配置合规检查。
- binary_analysis: 分析二进制文件（输入 file_path）。支持 ELF/PE/Mach-O/Java Class 格式，提取文件头、架构、安全特征（NX/PIE/ASLR/Stack Canary）。可用于恶意软件初步分析和逆向工程辅助。
- task_planner: 任务规划引擎（输入 task_type + description）。基于输入类型自动生成多步骤执行计划，支持文件分析、漏洞扫描、渗透测试、应急响应等场景。返回工具编排建议和执行顺序。
- rule_match: 规则匹配工具（输入 match_type + content/file_path）。使用 Sigma/YARA 规则匹配日志和文件，检测恶意软件、攻击行为、异常模式。支持三种模式：log(日志匹配)、file(文件匹配)、data(数据匹配)。返回匹配规则、严重等级和处置建议。
- knowledge_graph: 知识图谱工具（输入 operation + query/entity_id/content）。支持搜索实体(CVE、恶意软件、IP、域名)、查询关系、从文本提取实体、查找攻击路径。可用于威胁情报关联、攻击链溯源、漏洞影响评估。
- response_action: 响应动作工具（输入 action_type + params/threat_data）。执行自动响应动作：block_ip(阻断IP)、isolate_host(隔离主机)、notify(发送通知)、quarantine_file(隔离文件)、disable_account(禁用账户)、auto_respond(自动响应)。可用于应急响应、威胁处置、安全自动化。
- threat_intel: 外部威胁情报查询（输入 query + sources）。查询 Shodan/GreyNoise/AbuseIPDB，获取 IP 信誉、开放端口、已知恶意活动。当 ioc_lookup 结果不够深入时使用。
- planner: 调查规划引擎（输入 target + target_type）。根据目标类型自动生成结构化调查计划，返回分步调查步骤。**在开始复杂调查前必须调用此工具**，确保调查完整不遗漏。
- whois_lookup: WHOIS 注册信息查询（输入 domain）。返回注册商、注册时间、过期时间、注册人国家。用于判断域名可信度（新注册域名风险更高）。
- dns_lookup: DNS 记录查询（输入 domain + record_types）。返回 A/AAAA/MX/NS/TXT/CNAME 记录。用于分析域名基础设施。
- ssl_lookup: SSL 证书查询（输入 domain + port）。返回颁发者、有效期、SAN、指纹。用于判断域名可信度（免费证书+新域名=高风险）。

## 自主调查模式（分级 Planner）

**核心原则：简单查询直调工具，复杂调查走 Planner。**

### 何时直接调用工具（不走 Planner）：
- 单个 IP 查询 → 直接 `ip_threat_analysis`
- 单个 Hash 查询 → 直接 `hash_lookup`
- 单个 CVE 查询 → 直接 `cve_lookup`
- 单个域名快速查询 → 直接 `ioc_lookup`
- 简单日志分析 → 直接 `log_analysis`
- ATT&CK 映射 → 直接 `rag_search`

### 何时必须调用 Planner：
- 域名调查（是否钓鱼/仿冒）→ `planner` → 6 步深度调查
- 告警研判（多步攻击链）→ `planner` → 先拆链提取 IoC，再逐个调查
- PCAP 流量分析 → `planner` → 协议/异常/IoC/情报/攻击链
- 多 IoC 关联分析 → `planner` → 批量查询 + 交叉关联
- 事件响应 → `planner` → 态势评估 + IoC + 情报 + 处置

### 调查流程（Planner 模式）：
1. **规划**：调用 `planner` 生成分级计划（Mini 2-4步 / Full 6-12步）
2. **执行**：按计划逐步调用工具，每步结果编号为 E1, E2, E3...
3. **条件执行**：非必需步骤（required: false）在前置无结果时跳过
4. **综合**：所有步骤完成后，给出结论并**引用证据编号**

### 条件执行规则：
- RAG 查询仅在 IoC 查询有结果时执行（有情报才查知识库）
- 深度情报（threat_intel）仅在 IoC 发现威胁时执行
- 知识图谱查询仅在有明确实体时执行

## 输入格式自动识别
系统会自动检测用户输入的格式类型并推荐工具链。你应根据检测结果优先使用推荐的工具：
- pcap/pcapng 文件 → pcap_analysis → ip_threat_analysis → ioc_lookup
- 压缩包 (zip/rar/7z) → archive_analysis → (解压后对子文件递归分析)
- 二进制文件 (exe/dll/elf) → binary_analysis → hash_lookup
- 配置文件 (json/yaml/xml/env) → config_parser
- API 文档 (swagger/openapi) → api_doc_parser → vuln_scan
- 日志文本 → log_analysis → ioc_lookup (对提取的 IoC)
- Sigma/YARA 规则 → rule_match (加载到规则引擎)
- IoC 列表 (多行 IP/域名/哈希) → ioc_lookup (批量)
- 如果用户没有提供文件路径但提到了文件，询问路径或使用 task_planner 规划

## 标准调查流程（遇到 IoC 时必须按流程串联工具，不可跳过）

**域名调查流程（遇到可疑域名时必须执行）：**
1. `ioc_lookup` — 查询威胁情报（VT/OTX）
2. `whois_lookup` — 查询 WHOIS 注册信息（注册商/注册时间/过期时间）
3. `dns_lookup` — 查询 DNS 记录（A/MX/NS/TXT）
4. `ssl_lookup` — 查询 SSL 证书（颁发者/有效期/SAN）
5. `web_search` — 搜索域名关联的安全事件
6. `knowledge_graph` — 查询知识图谱关联实体
7. 综合结论（必须引用 E1-E7 证据编号）

**IP 调查流程：**
1. `ip_threat_analysis` — 地理位置 + 信誉评分
2. `ioc_lookup` — 多源情报查询
3. 如有上下文 → `knowledge_graph` 搜索关联实体

**Hash 调查流程：**
1. `hash_lookup` — VT + MalwareBazaar 查询
2. 如有文件路径 → `binary_analysis` 结构分析

**告警研判流程：**
1. 解析进程链/行为链
2. 对所有 IoC（IP/域名/哈希）逐个调用 `ioc_lookup`
3. 关联 ATT&CK 技术
4. 给出事实/推断分离的结论

你必须严格使用以下 JSON 格式之一回复，不要输出其他内容：

调用工具：
{"thought": "你的分析思路", "action": "工具名", "action_input": {"参数名": "参数值"}}

给出最终答案：
{"final_answer": "你的回答", "confidence": 0.9, "evidence": ["证据1", "证据2"]}

重要规则：
1. 每次回复只能包含一个 JSON 对象，不要在 JSON 前后添加任何文字
2. **必须使用工具的情况（不可跳过）：**
   - 用户提到 CVE 编号（如 CVE-2024-xxxx）→ 必须调用 cve_lookup
    - 用户要求列出、筛选、统计或交集查询 CVE / KEV，尤其包含年份、CVSS、KEV、严重等级等条件 → 必须调用 cve_catalog
   - 用户提到域名、IP、Hash、URL 等 IoC 指标 → 必须调用 ioc_lookup
   - 用户要求分析某个 IP → 必须调用 ip_threat_analysis
   - 用户要求"搜索"、"查询最新"、"联网查找"等时效性信息 → 必须调用 web_search
   - 用户要求从知识库检索 → 必须调用 rag_search
   - 用户上传 pcap 文件（消息中包含 [文件路径: ...] 或 .pcap/.pcapng 路径）→ 必须调用 pcap_analysis，参数 pcap_path 填文件路径。不要用 web_search 搜索 pcap 文件内容。分析完成后根据返回的 external_ips_for_lookup 和 domains_for_lookup 自动串联 ip_threat_analysis 和 ioc_lookup
   - 用户粘贴日志文本（包含时间戳、syslog 格式、Apache/Nginx 日志、Windows Event 等多行文本）→ 必须调用 log_analysis，参数 log_content 填日志原文。**注意区分：日志文本用 log_analysis，pcap 文件用 pcap_analysis，两者不可混淆**
3. 只有纯概念性问题（如"什么是XSS"、"解释下SQL注入"）才可以不调用工具直接回答
4. **每个问题最多调用 10 次工具**。PCAP 分析等复杂任务可串联多个工具，但应在合理范围内
5. 工具返回结果后，无论结果是否理想，都必须立即整合信息给出 final_answer。**工具结果必须格式化为结构化 markdown，禁止输出原始 JSON**：
   - `cve_lookup` → 表格：CVE编号/类型/评分/影响组件/描述/修复建议
   - `cve_catalog` → 表格：CVE编号/严重等级/评分/发布日期 + 统计摘要
   - `ioc_lookup`（单个）→ 表格：指标/类型/风险评分/风险等级/来源详情
   - `ioc_lookup`（批量）→ 表格：指标/类型/风险评分/风险等级（每行一个IoC）
   - `ip_threat_analysis` → 表格：IP/地理位置/ISP/威胁评分/各维度详情
   - `threat_intel` → 表格：来源/风险评分/关键发现 + 综合摘要
   - `log_analysis` → 分区展示：IoC列表(表格) + 攻击模式(表格) + 威胁评估
   - `hash_lookup` → 表格：哈希/类型/检测率/文件类型/恶意软件家族/信誉分
   - `nmap_scan` → 表格：端口/状态/服务/版本 + 主机摘要
   - `vuln_scan` → 表格：漏洞名/严重等级/类型/描述/修复建议
   - `dir_scan` → 表格：路径/状态码/内容类型/大小
   - `rule_match` → 表格：规则名/类型/严重等级/置信度/匹配条件/建议
   - `knowledge_graph` → 表格：实体名/类型/置信度/来源 + 关系列表
   - `task_planner` → 编号列表：步骤/工具/描述/依赖/优先级
   - `archive` → 表格：文件名/类型/大小/可疑标记
   - `api_doc_parser` → 表格：路径/方法/参数/认证要求 + 安全风险列表
   - `config_parser` → 分区：敏感信息(表格) + 安全问题(列表) + 结构摘要
   - `binary_analysis` → 表格：属性/值（格式/架构/安全特征/节信息）
   - `encoding_tool` → 代码块展示编解码结果
   - `web_search` → 编号列表：标题/URL/摘要
   - `response_action` → 表格：动作/状态/消息/详情
6. 如果工具失败或无结果，基于已有知识回答，并说明信息来源
7. **联网搜索 web_search 只允许单次调用**：拿到搜索结果后必须立即总结并给出 final_answer，禁止为了“继续查找”而重复调用 web_search；如果结果仍不足，直接说明证据不足并建议缩小检索范围
         - 对于软件著作权、登记流程、一般政策/法规/定义类问题，若用户没有明确要求“最新”或“官方实时变化”，优先直接基于已有知识回答，不要盲目调用 web_search。
         - 若 web_search 返回结果与问题明显不相关，必须判定为证据不足，不能把无关结果整理成结论。
8. **数据准确性（最高优先级）：**
   - **禁止自行换算或编造数值**。工具返回的 duration_s、total_packets、total_bytes、anomaly_count 等数值必须原样引用；不得擅自换算成小时/MB，也不得替换成“更顺眼”的数字。
   - **禁止编造未观察到的事实**。不要在工具未明确给出时，擅自补写主机 IP、地理位置、域名解析结果、文件哈希、payload 内容、认证成功、数据外泄、攻击成功等结论。
   - **事实与推断必须分开**。将“已确认事实”和“疑似/推断”分开表述；凡是没有直接证据支撑的内容，必须使用“疑似 / 可能 / 不能排除”，不能写成已确认事实。
   - **检测到异常时必须逐条列出**。如果工具返回了 anomalies 数组，必须列出每个异常的类型、严重程度和详情，不能只写"检测到 N 个异常"而不展开。
    - **标注数据来源**。在 final_answer 末尾的 evidence 数组中，只列出本次分析实际调用并返回结果的数据来源；不要写未调用、未返回或仅推断出来的来源（例如只有在工具实际返回时才可写 "VirusTotal"、"OTX"、"ip-api.com"、"abuseipdb.com"）。
   - **标注置信度**。final_answer 顶层 confidence 取值 0.0-1.0；evidence 数组只放证据来源，不要把 confidence 混进证据列表。
9. **证据引用规则（结论必须有据可查）：**
   - **每次工具调用都是一条证据**。按调用顺序编号为 E1、E2、E3...
   - **结论必须引用证据编号**。例如："域名疑似钓鱼（E1: VT 13/91 恶意；E2: 注册仅 3 天；E3: 仿冒 Microsoft 登录页）"
   - **无证据支撑的结论必须标注为推断**。例如："可能已失陷（无直接证据，基于行为模式推断）"
   - **证据表格**：复杂调查的 final_answer 末尾必须附上证据表格：
     ```
     | 编号 | 来源工具 | 关键发现 |
     |------|----------|----------|
     | E1 | ioc_lookup | VT 13/91 恶意 |
     | E2 | web_search | 注册时间仅 3 天 |
     ```
   - **上下文来源透明**。如果 IoC 查询的值来自 pcap 分析中的 DNS 查询，必须明确说明“该域名在 pcap 流量的 DNS 查询中发现”。
   - **PCAP 文件名一致性**。如果 pcap_analysis 返回 pcap_identity.display_filename 或 source_path，报告标题和正文必须使用该文件名/路径标识，不得编造其他文件名。
   - **时间基准一致性**。如果 pcap summary 的 time_basis 为 relative，正文只能用“抓包内先后顺序 / T+xx / 第 xx 秒”表达时间，不得写成具体年月日；只有在 time_basis 为 epoch 且 start_time/end_time 非空时才可写绝对时间。
   - **不得暴露内部截断/上下文限制**。不要对用户说"工具输出被截断"、"输出限制放宽后重试"等内部工程信息。若关键信息不足，必须自行重试可用工具；仍不足时说明"当前证据不足以给出确定结论"，而不是要求用户解决系统限制。
   - **威胁等级判定需区分行为证据和情报证据**。PCAP 中的 high/critical 行为异常（如端口扫描、暴力连接、高流量外联）不能仅因 IP 信誉分低就降为低危；若降级，必须明确解释降级依据和置信度。反过来，信誉分正常也不能自动判定安全，必须以行为证据优先。
   - **禁止基于名称相似性推断关联**。如果 web_search 返回的结果中提到的品牌/组织与用户查询的 IoC 没有直接因果关系，禁止将其作为证据。例如搜索 "abc-login-security.com" 返回 "Phishing site impersonates ABC Bank"，不能直接推断该域名就是仿冒 ABC Bank 的钓鱼站，除非有直接证据（如 WHOIS、页面内容）证明关联。
   - **禁止引用用户未提供的数据源**。如果用户只提供了文本描述（而非 pcap 文件），禁止编造具体的流量统计数据（包数、字节数、流记录、DNS 记录等）。每条证据必须可追溯到具体的工具调用结果。
   - **web_search 结果必须验证相关性**。搜索结果的标题必须包含查询关键词或其变体，否则必须丢弃该结果，不能用于结论。如果所有结果都不相关，直接判定为"证据不足"。

9. **PCAP 研判输出模板（response_type: pcap）**
   - 当用户要求“分析流量包 / pcap / pcapng”时，final_answer 必须围绕以下结构输出：
     1. `## 结论`：一句话给出是否存在威胁与威胁等级
     2. `## 关键证据`：按“已确认事实”列出，优先包含 DNS、HTTP、C2、下载、异常类型
     3. `## 异常概览`：逐条列出 anomalies；若数量很多，可按同类/同源合并，但必须保留数量、源/目的、严重度和细节
     4. `## 研判与置信度`：明确区分“已确认事实”和“推断/疑似”，不要把推断写成事实
     5. `## 待确认项`：仅列出仍需主机日志/EDR/代理日志验证的内容
     6. `## 处置建议`：给出隔离、阻断、取证、排查建议
     7. `## 数据来源`：列出本次使用的工具与情报源
   - PCAP 场景里，只有在工具明确给出直接证据时，才可写“已失陷 / 已成功认证 / 已外泄”；否则必须写“疑似 / 不能排除 / 需要进一步验证”。
   - 如果工具返回的 summary.time_basis 为 relative，禁止写“2024-xx-xx”这类绝对时间；如果工具没有明确给出地理位置，也不要自行补写国家、城市或 ISP。

## 结构化输出模板

根据查询类型，final_answer 必须按以下模板输出结构化 markdown。若需要标注类型，可在外层 JSON 额外加入 response_type 字段（纯概念性问题不需要），但不要破坏 final_answer / confidence / evidence 的基本结构。

### CVE 漏洞查询模板（response_type: "cve"）

## {cve_id} - {漏洞简述}

**风险等级：{Critical/High/Medium/Low}** | **CVSS 评分：{score}** | **漏洞类型：{type}**

### 基本信息

| 项目 | 详情 |
|------|------|
| CVE 编号 | {cve_id} |
| 漏洞类型 | {type}（如远程代码执行、SQL注入等） |
| CVSS 评分 | {score}（{vector}） |
| 影响组件 | {affected_component} |
| 披露日期 | {disclosure_date} |
| 攻击复杂度 | {complexity} |

### 影响版本

- {version_range_1}
- {version_range_2}

### 漏洞描述

{详细描述漏洞原理和攻击方式}

### 修复建议

1. {建议1}
2. {建议2}

### 数据来源

- {source_1}
- {source_2}

### CVE / KEV 结构化筛选模板（response_type: "cve_catalog"）

## CVE / KEV 结构化查询结果

### 结论

{summary_text}

### 统计摘要

| 指标 | 数值 |
|------|------|
| 命中总数 | {matched_count} |
| KEV 命中数 | {kev_count} |
| KEV 命中率 | {kev_hit_rate} |
| 返回条数 | {returned_count} |

### 分布统计

- 按年份：{by_year}
- 按严重级别：{by_severity}
- KEV 按年份：{kev_by_year}
- KEV 按严重级别：{kev_by_severity}

### 样本结果

{items}

### 说明

- 如果返回条数小于命中总数，必须说明当前仅展示样本，不代表全集。
- 如果问题要求交集统计，应优先引用 stats，而不是重新推断。
- 如果结果包含 KEV 命中，必须说明这些 CVE 同时满足 NVD 条件与 KEV 交集条件。

### IoC 威胁情报模板（response_type: "ioc"）

## IoC 分析报告 - {indicator_value}

**指标类型：{IP/域名/Hash/URL}** | **综合威胁评分：{score}/100**

### 多源情报汇总

| 来源 | 评分 | 标签 | 状态 |
|------|------|------|------|
| VirusTotal | {score}/100 | {tags} | {status} |
| AbuseIPDB | {score}/100 | {tags} | {status} |
| OTX | {score}/100 | {tags} | {status} |

### 关联信息

- **首次发现：** {first_seen}
- **最近活动：** {last_seen}
- **关联家族：** {malware_family}
- **关联 Campaign：** {campaign}

### 处置建议

1. {建议1}
2. {建议2}

### 数据来源

- {source_1}

### IP 威胁分析模板（response_type: "ip"）

## IP 威胁分析报告 - {ip_address}

**归属地：{country}, {city}** | **ISP：{isp}** | **威胁评分：{score}/100**

### 评分构成

| 维度 | 分值 | 权重 | 说明 |
|------|------|------|------|
| 恶意活动 | {score} | {weight} | {detail} |
| 信誉评分 | {score} | {weight} | {detail} |
| 地理风险 | {score} | {weight} | {detail} |
| 行为分析 | {score} | {weight} | {detail} |

### 处置建议

1. {建议1}
2. {建议2}

### 数据来源

- {source_1}
"""


MAX_TOOL_CALLS = 10
WEB_SEARCH_TOOL_NAME = "web_search"
WEB_SEARCH_SINGLE_SHOT = True
CVE_CATALOG_TOOL_NAME = "cve_catalog"


def _collect_web_search_terms(text: str) -> list[str]:
    """Extract simple search terms for relevance gating.

    We keep the heuristic lightweight so it can run inline after a web search.
    Chinese runs are expanded into 4-character windows to catch phrases like
    "软件著作权" even when the original question is a full sentence.
    """
    normalized = (text or "").strip().lower()
    if not normalized:
        return []

    terms: list[str] = []
    token: list[str] = []
    token_is_cjk: bool | None = None

    def flush_token() -> None:
        nonlocal token, token_is_cjk
        if not token:
            return
        value = "".join(token)
        if token_is_cjk:
            if len(value) >= 4:
                for index in range(0, len(value) - 3):
                    terms.append(value[index:index + 4])
            elif len(value) >= 2:
                terms.append(value)
        else:
            if len(value) >= 2:
                terms.append(value)
        token = []
        token_is_cjk = None

    for char in normalized:
        is_cjk = "\u4e00" <= char <= "\u9fff"
        if char.isalnum() or is_cjk:
            if token and token_is_cjk != is_cjk:
                flush_token()
            token.append(char)
            token_is_cjk = is_cjk
        else:
            flush_token()

    flush_token()

    deduped: list[str] = []
    seen: set[str] = set()
    for term in terms:
        if term and term not in seen:
            seen.add(term)
            deduped.append(term)
    return deduped


def _web_search_relevant_results(query: str, results: list[dict[str, str]]) -> list[dict[str, str]]:
    """Keep only results that actually overlap with the query."""
    terms = _collect_web_search_terms(query)
    if not terms:
        return results

    relevant: list[dict[str, str]] = []
    for result in results:
        haystack = " ".join([
            result.get("title", ""),
            result.get("snippet", ""),
            result.get("url", ""),
        ]).lower()
        matched = [term for term in terms if term in haystack]
        if matched and (len(matched) >= 2 or any(len(term) >= 4 for term in matched)):
            relevant.append(result)
    return relevant


def _build_web_search_insufficient(query: str) -> str:
    """Return a deterministic answer when search results are irrelevant."""
    lines = [
        "## 联网搜索结果摘要",
        f"查询：{query or '（未提供具体查询）'}",
        "当前搜索结果与问题相关性不足，不能据此给出可靠结论。",
        "建议改用更具体的关键词，或优先查看官方/权威来源后再判断。",
    ]
    return "\n".join(lines)


def _dedup_key(tool: str, action_input: dict[str, Any]) -> str:
    """Generate dedup key from tool name + primary query field."""
    # Extract the core query value, ignoring secondary params like max_results
    query = action_input.get("query") or action_input.get("cve_id") or action_input.get("value") or action_input.get("ip") or action_input.get("message") or ""
    return f"{tool}:{str(query).strip().lower()}"


def _build_web_search_fallback(query: str, tool_result: dict[str, Any]) -> str:
    """Build a concise final answer from web search results.

    Used as a guardrail when the model keeps asking to search again instead of
    synthesizing. We intentionally keep this conservative and source-oriented.
    """
    data = tool_result.get("data", {}) or {}
    results = _normalize_web_search_results(data.get("results", []))
    relevant_results = _web_search_relevant_results(query, results)
    lines = [
        "## 联网搜索结果摘要",
        f"查询：{query or '（未提供具体查询）'}",
    ]

    if not relevant_results:
        lines.append("当前搜索结果与问题相关性不足，不能据此给出可靠结论。")
        lines.append("建议改用更具体的关键词，或优先查看官方/权威来源后再判断。")
        return "\n".join(lines)

    lines.append("基于当前可见结果，优先参考以下权威来源：")
    for idx, item in enumerate(results[:5], start=1):
        title = (item.get("title") or "").strip()
        snippet = (item.get("snippet") or "").strip()
        url = (item.get("url") or "").strip()
        if not title and not snippet and not url:
            continue
        entry = f"{idx}. {title or '未命名结果'}"
        if snippet:
            entry += f" — {snippet}"
        if url:
            entry += f" ({url})"
        lines.append(entry)

    lines.append("建议优先查看论文、数据集主页、官方文档或基准报告，再基于这些来源做最终判断。")
    return "\n".join(lines)


def _build_cve_catalog_fallback(tool_result: dict[str, Any]) -> str:
    """Build a deterministic final answer from catalog query results."""
    data = tool_result.get("data") if isinstance(tool_result.get("data"), dict) else {}
    stats = data.get("stats") if isinstance(data.get("stats"), dict) else {}
    items = data.get("items") if isinstance(data.get("items"), list) else []
    evidence_rows = data.get("evidence") if isinstance(data.get("evidence"), list) else []

    lines = ["## CVE / KEV 结构化查询结果"]

    summary_text = str(data.get("summary_text", "")).strip()
    if summary_text:
        lines.append("")
        lines.append("## 结论")
        lines.append(summary_text)

    lines.append("")
    lines.append("## 统计摘要")
    lines.append(f"- 命中总数：{data.get('matched_count', 0)}")
    lines.append(f"- KEV 命中数：{data.get('kev_count', 0)}")
    lines.append(f"- KEV 命中率：{stats.get('kev_hit_rate', 0.0)}")
    lines.append(f"- 返回条数：{data.get('returned_count', len(items))}")

    if stats:
        lines.append("")
        lines.append("## 分布统计")
        lines.append(f"- 按年份：{stats.get('by_year', {})}")
        lines.append(f"- 按严重级别：{stats.get('by_severity', {})}")
        lines.append(f"- KEV 按年份：{stats.get('kev_by_year', {})}")
        lines.append(f"- KEV 按严重级别：{stats.get('kev_by_severity', {})}")

    if items:
        lines.append("")
        lines.append("## 样本结果")
        lines.append("| CVE | doc_id | 披露时间 | CVSS | 严重级别 | KEV | KEV 日期 | 厂商 | 产品 | 来源 |")
        lines.append("|---|---|---|---|---|---|---|---|---|---|")
        for item in items[:10]:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"| {item.get('cve_id', '')} | {item.get('doc_id', '')} | {item.get('published', '')} | {item.get('cvss_score', 0.0)} | {item.get('severity', 'UNKNOWN')} | {'是' if item.get('is_kev') else '否'} | {item.get('kev_date', '')} | {item.get('vendor', '')} | {item.get('product', '')} | {item.get('source_path', '')} |"
            )

    if evidence_rows:
        lines.append("")
        lines.append("## 证据")
        lines.append("| CVE | 来源类型 | 来源路径 | doc_id | 关键日期 | 说明 |")
        lines.append("|---|---|---|---|---|---|")
        for entry in evidence_rows[:20]:
            if not isinstance(entry, dict):
                continue
            key_dates = entry.get("key_dates", {}) if isinstance(entry.get("key_dates"), dict) else {}
            key_dates_text = "; ".join(f"{k}={v}" for k, v in key_dates.items())
            lines.append(
                f"| {entry.get('cve_id', '')} | {entry.get('source_type', '')} | {entry.get('source_path', '')} | {entry.get('doc_id', '')} | {key_dates_text} | {entry.get('note', '')} |"
            )

    lines.append("")
    lines.append("## 说明")
    lines.append("- 如果返回条数小于命中总数，这里只展示样本，不代表全集。")
    lines.append("- KEV 命中表示该 CVE 同时满足 NVD 记录与 KEV 交集条件。")

    return "\n".join(lines).strip()


def _last_user_message(messages: list[dict[str, Any]]) -> str:
    """Extract the last user message content from message list."""
    for message in reversed(messages):
        if message.get("role") == "user":
            return str(message.get("content", "")).strip()
    return ""


def _build_llm_unavailable_fallback(messages: list[dict[str, Any]], error: str) -> str:
    """Build a friendly offline answer when the model backend is unavailable.

    We keep the fallback intentionally lightweight and deterministic so that the
    chat UI does not surface raw transport exceptions to the user.
    """
    query = _last_user_message(messages)
    lowered = query.lower()

    if any(keyword in lowered for keyword in ("postgres", "postgresql", "数据库", "sql", "入门", "基础", "使用")):
        return "\n".join([
            "## PostgreSQL 入门",
            "",
            "当前在线大模型暂时不可用，我先给你一个离线版的快速入门：",
            "",
            "1. PostgreSQL 是关系型数据库，适合存储结构化数据。",
            "2. 常用连接方式是 `psql`、DBeaver、DataGrip，或应用里的数据库驱动。",
            "3. 常见基础操作包括 `CREATE DATABASE`、`CREATE TABLE`、`INSERT`、`SELECT`、`UPDATE`、`DELETE`。",
            "4. 初学时重点掌握主键、外键、索引、事务和权限管理。",
            "5. 生产环境里建议补上备份恢复、用户最小权限和监控告警。",
            "",
            "如果你愿意，我也可以继续按“安装 -> 连接 -> 建库建表 -> 查询 -> 权限 -> 备份”这个顺序给你展开。",
        ]).strip()

    if any(keyword in lowered for keyword in ("入门", "基础", "解释", "是什么", "怎么", "如何")):
        return "\n".join([
            "## 离线兜底回答",
            "",
            "当前在线大模型暂时不可用，我先用离线模式给你一个简洁版本：",
            "",
            f"你刚才的问题是：{query or '（未提供具体问题）'}",
            "",
            "我建议你把问题再缩小一点，或者告诉我你更关心的是概念、命令示例，还是实际部署。",
        ]).strip()

    return "\n".join([
        "## 当前模型暂时不可用",
        "",
        "我这边检测到外部 LLM 后端暂时无法响应，所以先切换到离线兜底模式。",
        query and f"你刚才的问题是：{query}" or "",
        "",
        "你可以稍后重试，或者把问题拆小一点，我会尽量先给你一个不依赖外部模型的基础答复。",
    ]).strip()


def _normalize_web_search_results(results: Any) -> list[dict[str, str]]:
    """Coerce web search results into dict-shaped rows for safe formatting."""
    if isinstance(results, dict):
        results = [results]
    elif isinstance(results, str):
        results = [results]
    elif not isinstance(results, list):
        return []

    normalized: list[dict[str, str]] = []
    for item in results:
        if isinstance(item, dict):
            normalized.append({
                "title": str(item.get("title", "")).strip(),
                "snippet": str(item.get("snippet", "")).strip(),
                "url": str(item.get("url", "")).strip(),
            })
        elif isinstance(item, str):
            text = item.strip()
            if text:
                normalized.append({"title": text, "snippet": "", "url": ""})
        else:
            text = str(item).strip()
            if text:
                normalized.append({"title": text, "snippet": "", "url": ""})

    return normalized


def _extract_json_string_prefix(text: str, key: str) -> str | None:
    """Extract the currently streamed prefix of a JSON string value.

    The LLM is instructed to return JSON. During streaming, that JSON is often
    incomplete, so full parsing cannot work until the final closing brace. This
    helper finds `"key": "` and decodes the string value prefix that has already
    arrived, even if the string/object is not closed yet.
    """
    key_literal = json.dumps(key)
    key_pos = text.find(key_literal)
    if key_pos < 0:
        return None

    colon_pos = text.find(":", key_pos + len(key_literal))
    if colon_pos < 0:
        return None

    value_start = colon_pos + 1
    while value_start < len(text) and text[value_start].isspace():
        value_start += 1
    if value_start >= len(text) or text[value_start] != '"':
        return None

    raw_value = text[value_start + 1:]
    chars: list[str] = []
    i = 0
    while i < len(raw_value):
        ch = raw_value[i]
        if ch == '"':
            break
        if ch != "\\":
            chars.append(ch)
            i += 1
            continue

        if i + 1 >= len(raw_value):
            break
        esc = raw_value[i + 1]
        if esc == "u":
            hex_part = raw_value[i + 2:i + 6]
            if len(hex_part) < 4 or any(c not in "0123456789abcdefABCDEF" for c in hex_part):
                break
            chars.append(chr(int(hex_part, 16)))
            i += 6
            continue
        escape_map = {
            '"': '"',
            "\\": "\\",
            "/": "/",
            "b": "\b",
            "f": "\f",
            "n": "\n",
            "r": "\r",
            "t": "\t",
        }
        chars.append(escape_map.get(esc, esc))
        i += 2

    return "".join(chars)


class ReActAgent:
    """ReAct reasoning agent.

    Loop: Thought → Action → Observation
    Terminates on: final_answer, max_turns, consecutive failures
    """

    def __init__(
        self,
        llm_router: Any,
        tool_registry: Any,
        max_turns: int = 6,
        max_tool_retries: int = 3,
        compress_interval: int = 4,
        obs_max_tokens: int = 2000,
    ):
        self.llm = llm_router
        self.tools = tool_registry
        self.max_turns = max_turns
        self.max_tool_retries = max_tool_retries
        self.compress_interval = compress_interval
        self.obs_max_tokens = obs_max_tokens

    async def run(
        self,
        messages: list[dict[str, Any]],
        tenant_id: str,
        trace_id: str,
        session_id: str = "",
        user_id: str = "",
    ) -> ReActResult:
        """Execute the ReAct loop."""
        working_messages = [{"role": "system", "content": SYSTEM_PROMPT}] + list(messages)
        tool_calls_log: list[dict[str, Any]] = []
        total_tokens = 0
        start_time = time.time()
        consecutive_failures = 0
        tool_call_count = 0
        seen_tool_calls: set[str] = set()
        web_search_count = 0
        last_web_search_query = ""
        last_web_search_result: dict[str, Any] | None = None
        last_cve_catalog_result: dict[str, Any] | None = None

        # Start decision trace
        query = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                query = str(msg.get("content", ""))
                break
        
        decision_tracker.start_trace(
            trace_id=trace_id,
            session_id=session_id or trace_id,
            user_id=user_id or "unknown",
            tenant_id=tenant_id,
            query=query,
        )

        for turn in range(1, self.max_turns + 1):
            # Compress if needed
            if should_compress(len(working_messages), self.compress_interval):
                working_messages = compress_history(
                    working_messages, keep_recent=self.compress_interval
                )
                # Track compression
                decision_tracker.add_step(
                    trace_id=trace_id,
                    turn=turn,
                    decision_type="compress",
                    content="上下文压缩",
                    metadata={"message_count": len(working_messages)},
                )

            # Call LLM
            from app.llm.router import LLMRequest
            request = LLMRequest(
                messages=working_messages,
                tools=None,  # ReAct uses prompt-based JSON, not native function calling
                trace_id=trace_id,
            )

            llm_start = time.time()
            response = await self.llm.complete(request)
            llm_duration_ms = int((time.time() - llm_start) * 1000)
            total_tokens += response.usage.get("total_tokens", 0)

            # Parse LLM output
            parsed = parse_llm_json(response.content)

            # Check for final answer
            if "final_answer" in parsed:
                # Track final answer
                decision_tracker.add_final_answer(
                    trace_id=trace_id,
                    answer=parsed["final_answer"],
                    confidence=parsed.get("confidence", 0.0),
                )
                decision_tracker.end_trace(trace_id, success=True)
                
                return ReActResult(
                    success=True,
                    final_answer=parsed["final_answer"],
                    turns_used=turn,
                    tool_calls=tool_calls_log,
                    total_tokens=total_tokens,
                    total_latency_ms=int((time.time() - start_time) * 1000),
                )

            # Check for error in parse
            if parsed.get("error") == "parse_failed":
                consecutive_failures += 1
                
                # Track error
                decision_tracker.add_error(
                    trace_id=trace_id,
                    turn=turn,
                    error=f"JSON 解析失败 (尝试 {consecutive_failures}/{self.max_tool_retries})",
                    metadata={"raw_content": response.content[:200]},
                )
                
                if consecutive_failures >= self.max_tool_retries:
                    decision_tracker.end_trace(trace_id, success=False, error="达到最大重试次数")
                    return ReActResult(
                        success=False,
                        final_answer=f"Agent failed: LLM output could not be parsed after {consecutive_failures} attempts.",
                        turns_used=turn,
                        tool_calls=tool_calls_log,
                        total_tokens=total_tokens,
                    )
                # Retry with error feedback
                working_messages.append({
                    "role": "assistant",
                    "content": response.content,
                })
                working_messages.append({
                    "role": "user",
                    "content": (
                        "你的输出不是有效的 JSON。请严格按照以下格式输出：\n"
                        '{"thought": "...", "action": "tool_name", "action_input": {...}}\n'
                        '或直接给出最终答案：\n'
                        '{"final_answer": "...", "confidence": 0.9, "evidence": [...]}'
                    ),
                })
                continue

            # Extract action
            action = parsed.get("action")
            action_input = parsed.get("action_input", {})
            thought = parsed.get("thought", "")

            # Track thought
            if thought:
                decision_tracker.add_thought(
                    trace_id=trace_id,
                    turn=turn,
                    thought=thought,
                    confidence=parsed.get("confidence", 0.0),
                    metadata={"llm_latency_ms": llm_duration_ms},
                )

            if not action:
                # No action specified — treat as final answer attempt
                final_answer = parsed.get("thought", response.content)
                decision_tracker.add_final_answer(
                    trace_id=trace_id,
                    answer=final_answer,
                    confidence=parsed.get("confidence", 0.0),
                )
                decision_tracker.end_trace(trace_id, success=True)
                
                return ReActResult(
                    success=True,
                    final_answer=final_answer,
                    turns_used=turn,
                    tool_calls=tool_calls_log,
                    total_tokens=total_tokens,
                )

            # Dedup: check if same tool with same core query was already called
            call_key = _dedup_key(action, action_input)
            if call_key in seen_tool_calls:
                # Track duplicate detection
                decision_tracker.add_step(
                    trace_id=trace_id,
                    turn=turn,
                    decision_type="thought",
                    content=f"检测到重复工具调用: {action}",
                    metadata={"call_key": call_key, "duplicate": True},
                )
                
                if action == WEB_SEARCH_TOOL_NAME and last_web_search_result is not None:
                    final_answer = _build_web_search_fallback(last_web_search_query, last_web_search_result)
                    decision_tracker.add_final_answer(trace_id=trace_id, answer=final_answer, confidence=0.5)
                    decision_tracker.end_trace(trace_id, success=True)
                    return ReActResult(
                        success=True,
                        final_answer=final_answer,
                        turns_used=turn,
                        tool_calls=tool_calls_log,
                        total_tokens=total_tokens,
                        total_latency_ms=int((time.time() - start_time) * 1000),
                    )
                if action == CVE_CATALOG_TOOL_NAME and last_cve_catalog_result is not None:
                    final_answer = _build_cve_catalog_fallback(last_cve_catalog_result)
                    decision_tracker.add_final_answer(trace_id=trace_id, answer=final_answer, confidence=0.5)
                    decision_tracker.end_trace(trace_id, success=True)
                    return ReActResult(
                        success=True,
                        final_answer=final_answer,
                        turns_used=turn,
                        tool_calls=tool_calls_log,
                        total_tokens=total_tokens,
                        total_latency_ms=int((time.time() - start_time) * 1000),
                    )
                final_answer = thought or "基于已有信息，我无法获得更多数据，请尝试换个角度提问。"
                decision_tracker.add_final_answer(trace_id=trace_id, answer=final_answer, confidence=0.3)
                decision_tracker.end_trace(trace_id, success=True)
                return ReActResult(
                    success=True,
                    final_answer=final_answer,
                    turns_used=turn,
                    tool_calls=tool_calls_log,
                    total_tokens=total_tokens,
                )

            # Tool call limit
            if tool_call_count >= MAX_TOOL_CALLS:
                # Track tool call limit
                decision_tracker.add_step(
                    trace_id=trace_id,
                    turn=turn,
                    decision_type="error",
                    content=f"达到工具调用上限 ({MAX_TOOL_CALLS})",
                    metadata={"tool_call_count": tool_call_count},
                )
                
                if action == WEB_SEARCH_TOOL_NAME and last_web_search_result is not None:
                    final_answer = _build_web_search_fallback(last_web_search_query, last_web_search_result)
                    decision_tracker.add_final_answer(trace_id=trace_id, answer=final_answer, confidence=0.5)
                    decision_tracker.end_trace(trace_id, success=True)
                    return ReActResult(
                        success=True,
                        final_answer=final_answer,
                        turns_used=turn,
                        tool_calls=tool_calls_log,
                        total_tokens=total_tokens,
                        total_latency_ms=int((time.time() - start_time) * 1000),
                    )
                if action == CVE_CATALOG_TOOL_NAME and last_cve_catalog_result is not None:
                    final_answer = _build_cve_catalog_fallback(last_cve_catalog_result)
                    decision_tracker.add_final_answer(trace_id=trace_id, answer=final_answer, confidence=0.5)
                    decision_tracker.end_trace(trace_id, success=True)
                    return ReActResult(
                        success=True,
                        final_answer=final_answer,
                        turns_used=turn,
                        tool_calls=tool_calls_log,
                        total_tokens=total_tokens,
                        total_latency_ms=int((time.time() - start_time) * 1000),
                    )
                final_answer = thought or "已达到工具调用上限，请基于以上结果提问或换个角度提问。"
                decision_tracker.add_final_answer(trace_id=trace_id, answer=final_answer, confidence=0.3)
                decision_tracker.end_trace(trace_id, success=True)
                return ReActResult(
                    success=True,
                    final_answer=final_answer,
                    turns_used=turn,
                    tool_calls=tool_calls_log,
                    total_tokens=total_tokens,
                )

            if action == WEB_SEARCH_TOOL_NAME and web_search_count >= 1 and last_web_search_result is not None:
                final_answer = _build_web_search_fallback(last_web_search_query, last_web_search_result)
                decision_tracker.add_final_answer(trace_id=trace_id, answer=final_answer, confidence=0.5)
                decision_tracker.end_trace(trace_id, success=True)
                return ReActResult(
                    success=True,
                    final_answer=final_answer,
                    turns_used=turn,
                    tool_calls=tool_calls_log,
                    total_tokens=total_tokens,
                    total_latency_ms=int((time.time() - start_time) * 1000),
                )

            # Track tool call
            decision_tracker.add_action(
                trace_id=trace_id,
                turn=turn,
                tool_name=action,
                tool_input=action_input,
                confidence=parsed.get("confidence", 0.0),
            )

            # Add assistant message with tool_calls format
            tool_call_id = f"call_{trace_id}_{turn}"
            assistant_msg = {
                "role": "assistant",
                "content": response.content,
                "tool_calls": [{
                    "id": tool_call_id,
                    "type": "function",
                    "function": {
                        "name": action,
                        "arguments": json.dumps(action_input),
                    },
                }],
            }
            if response.reasoning_content:
                assistant_msg["reasoning_content"] = response.reasoning_content
            working_messages.append(assistant_msg)

            # Execute tool
            tool_start = time.time()
            tool_result = await self.tools.execute(
                name=action,
                arguments=action_input,
                trace_id=trace_id,
                tenant_id=tenant_id,
            )
            tool_duration_ms = int((time.time() - tool_start) * 1000)

            # Track tool observation
            decision_tracker.add_observation(
                trace_id=trace_id,
                turn=turn,
                tool_name=action,
                tool_output=tool_result,
                confidence=tool_result.get("confidence", 0.0),
                duration_ms=tool_duration_ms,
            )

            tool_call_count += 1
            seen_tool_calls.add(call_key)
            if action == WEB_SEARCH_TOOL_NAME and tool_result.get("success"):
                web_search_count += 1
                last_web_search_query = str(action_input.get("query", "")).strip()
                last_web_search_result = tool_result
            if action == CVE_CATALOG_TOOL_NAME and tool_result.get("success"):
                last_cve_catalog_result = tool_result

            tool_calls_log.append({
                "turn": turn,
                "tool": action,
                "input": action_input,
                "output": tool_result,
                "duration_ms": tool_duration_ms,
            })

            if action == WEB_SEARCH_TOOL_NAME and tool_result.get("success"):
                web_search_count += 1
                last_web_search_query = str(action_input.get("query", "")).strip()
                last_web_search_result = tool_result
                relevant_results = _web_search_relevant_results(
                    last_web_search_query,
                    _normalize_web_search_results((tool_result.get("data") or {}).get("results", [])),
                )
                if not relevant_results:
                    final_answer = _build_web_search_insufficient(last_web_search_query)
                    decision_tracker.add_final_answer(trace_id=trace_id, answer=final_answer, confidence=0.3)
                    decision_tracker.end_trace(trace_id, success=True)
                    return ReActResult(
                        success=True,
                        final_answer=final_answer,
                        turns_used=turn,
                        tool_calls=tool_calls_log,
                        total_tokens=total_tokens,
                        total_latency_ms=int((time.time() - start_time) * 1000),
                    )

            # Truncate observation
            obs_content = compact_tool_observation(tool_result, self.obs_max_tokens)

            working_messages.append({
                "role": "tool",
                "content": obs_content,
                "tool_call_id": tool_call_id,
            })

            # Check for tool failure
            if not tool_result.get("success"):
                consecutive_failures += 1
                # Track tool failure
                decision_tracker.add_error(
                    trace_id=trace_id,
                    turn=turn,
                    error=f"工具 {action} 执行失败: {tool_result.get('error', '未知错误')}",
                    metadata={"tool_name": action, "tool_input": action_input},
                )
            else:
                consecutive_failures = 0

        # Max turns reached
        final_answer = (
            _build_web_search_fallback(last_web_search_query, last_web_search_result)
            if last_web_search_result is not None
            else _build_cve_catalog_fallback(last_cve_catalog_result)
            if last_cve_catalog_result is not None
            else f"已达到最大推理轮次（{self.max_turns}）。请基于已有工具结果继续提问，或缩小问题范围后重试。"
        )
        
        # Track max turns reached
        decision_tracker.add_step(
            trace_id=trace_id,
            turn=self.max_turns,
            decision_type="error",
            content=f"达到最大推理轮次 ({self.max_turns})",
            metadata={"max_turns": self.max_turns},
        )
        decision_tracker.add_final_answer(trace_id=trace_id, answer=final_answer, confidence=0.3)
        decision_tracker.end_trace(trace_id, success=True)
        
        return ReActResult(
            success=True,
            final_answer=final_answer,
            turns_used=self.max_turns,
            tool_calls=tool_calls_log,
            total_tokens=total_tokens,
            total_latency_ms=int((time.time() - start_time) * 1000),
        )

    async def run_streaming(
        self,
        messages: list[dict[str, Any]],
        tenant_id: str,
        trace_id: str,
    ) -> AsyncIterator[TurnEvent]:
        """Execute ReAct loop with streaming events for WebSocket.

        Uses LLM streaming for all turns. Tokens are accumulated into a
        buffer and parsed after the stream completes for tool-call turns.
        For final-answer turns the answer text is streamed in real time.
        """
        working_messages = [{"role": "system", "content": SYSTEM_PROMPT}] + list(messages)
        tool_calls_log: list[dict[str, Any]] = []
        total_tokens = 0
        consecutive_failures = 0
        tool_call_count = 0
        seen_tool_calls: set[str] = set()
        web_search_count = 0
        last_web_search_query = ""
        last_web_search_result: dict[str, Any] | None = None
        last_cve_catalog_result: dict[str, Any] | None = None

        for turn in range(1, self.max_turns + 1):
            if should_compress(len(working_messages), self.compress_interval):
                working_messages = compress_history(
                    working_messages, keep_recent=self.compress_interval
                )

            from app.llm.router import LLMRequest
            request = LLMRequest(
                messages=working_messages,
                tools=None,  # ReAct uses prompt-based JSON, not native function calling
                trace_id=trace_id,
            )

            # Stream LLM response token by token
            accumulated = ""
            reasoning_content = ""
            answer_yielded = 0  # how many answer chars we've already yielded
            last_finish_reason = None
            try:
                async for chunk in self.llm.stream(request):
                    accumulated += chunk.get("content", "")
                    reasoning_content += chunk.get("reasoning_content", "")
                    if chunk.get("finish_reason"):
                        last_finish_reason = chunk["finish_reason"]
                    answer_prefix = _extract_json_string_prefix(accumulated, "final_answer")
                    if answer_prefix and len(answer_prefix) > answer_yielded:
                        yield TurnEvent(
                            type="answer_token",
                            turn=turn,
                            content=answer_prefix[answer_yielded:],
                        )
                        answer_yielded = len(answer_prefix)
            except Exception as e:
                if not tool_calls_log:
                    fallback = _build_llm_unavailable_fallback(messages, str(e))
                    for i in range(0, len(fallback), 20):
                        yield TurnEvent(type="answer_token", turn=turn, content=fallback[i:i+20])
                    total_tokens += max(1, len(fallback) // 4)
                    yield TurnEvent(type="usage", turn=turn, content={"total_tokens": total_tokens})
                    return

                yield TurnEvent(type="error", turn=turn, content={"error": "stream_failed", "raw": str(e)})
                return

            # Stream finished — parse the full response
            total_tokens += len(accumulated) // 4  # rough token estimate
            yield TurnEvent(type="usage", turn=turn, content={"total_tokens": total_tokens})
            parsed = parse_llm_json(accumulated)
            logger.info("Turn %d LLM response (finish=%s): %s", turn, last_finish_reason, accumulated[:200])

            # If response was truncated (hit max_tokens), auto-continue
            if last_finish_reason == "length" and "final_answer" not in parsed:
                partial = _extract_json_string_prefix(accumulated, "final_answer")
                if partial and len(partial) > answer_yielded:
                    for i in range(answer_yielded, len(partial), 20):
                        yield TurnEvent(type="answer_token", turn=turn, content=partial[i:i+20])
                    answer_yielded = len(partial)
                # Inject a continuation prompt and let the loop do another turn
                working_messages.append({"role": "assistant", "content": accumulated})
                working_messages.append({
                    "role": "user",
                    "content": "继续上一条回复，从断点处接着写，保持相同的格式和详细程度，不要重复已写内容。",
                })
                # Reset for next turn — don't return, let the loop continue
                consecutive_failures = 0
                continue

            if "final_answer" in parsed:
                # Yield any remaining answer text not yet streamed
                answer_text = parsed["final_answer"]
                while answer_yielded < len(answer_text):
                    yield TurnEvent(type="answer_token", turn=turn, content=answer_text[answer_yielded:answer_yielded+20])
                    answer_yielded += 20
                return

            if parsed.get("error") == "parse_failed":
                consecutive_failures += 1
                yield TurnEvent(type="error", turn=turn, content={"error": "parse_failed", "raw": accumulated})
                if consecutive_failures >= self.max_tool_retries:
                    return
                working_messages.append({"role": "assistant", "content": accumulated})
                working_messages.append({
                    "role": "user",
                    "content": '请输出有效 JSON: {"thought":"...","action":"tool","action_input":{...}} 或 {"final_answer":"...","confidence":0.9,"evidence":[...]}',
                })
                continue

            action = parsed.get("action")
            logger.info("Turn %d parsed action=%s, input=%s", turn, action, parsed.get("action_input", {}))
            if not action:
                answer_text = parsed.get("thought", accumulated)
                for i in range(0, len(answer_text), 20):
                    yield TurnEvent(type="answer_token", turn=turn, content=answer_text[i:i+20])
                return

            action_input = parsed.get("action_input", {})
            thought_text = parsed.get("thought", "")

            # Dedup: same tool + same core query already called
            call_key = _dedup_key(action, action_input)
            if call_key in seen_tool_calls:
                if action == WEB_SEARCH_TOOL_NAME and last_web_search_result is not None:
                    fallback = _build_web_search_fallback(last_web_search_query, last_web_search_result)
                    for i in range(0, len(fallback), 20):
                        yield TurnEvent(type="answer_token", turn=turn, content=fallback[i:i+20])
                    return
                if action == CVE_CATALOG_TOOL_NAME and last_cve_catalog_result is not None:
                    fallback = _build_cve_catalog_fallback(last_cve_catalog_result)
                    for i in range(0, len(fallback), 20):
                        yield TurnEvent(type="answer_token", turn=turn, content=fallback[i:i+20])
                    return
                fallback = thought_text or "基于已有信息，我无法获得更多数据，请尝试换个角度提问。"
                for i in range(0, len(fallback), 20):
                    yield TurnEvent(type="answer_token", turn=turn, content=fallback[i:i+20])
                return

            # Tool call limit
            if tool_call_count >= MAX_TOOL_CALLS:
                if action == WEB_SEARCH_TOOL_NAME and last_web_search_result is not None:
                    fallback = _build_web_search_fallback(last_web_search_query, last_web_search_result)
                    for i in range(0, len(fallback), 20):
                        yield TurnEvent(type="answer_token", turn=turn, content=fallback[i:i+20])
                    return
                if action == CVE_CATALOG_TOOL_NAME and last_cve_catalog_result is not None:
                    fallback = _build_cve_catalog_fallback(last_cve_catalog_result)
                    for i in range(0, len(fallback), 20):
                        yield TurnEvent(type="answer_token", turn=turn, content=fallback[i:i+20])
                    return
                fallback = thought_text or "已达到工具调用上限，请基于以上结果提问或换个角度提问。"
                for i in range(0, len(fallback), 20):
                    yield TurnEvent(type="answer_token", turn=turn, content=fallback[i:i+20])
                return

            if action == WEB_SEARCH_TOOL_NAME and web_search_count >= 1 and last_web_search_result is not None:
                fallback = _build_web_search_fallback(last_web_search_query, last_web_search_result)
                for i in range(0, len(fallback), 20):
                    yield TurnEvent(type="answer_token", turn=turn, content=fallback[i:i+20])
                return

            tool_call_id = f"call_{trace_id}_{turn}"

            yield TurnEvent(type="thought", turn=turn, content={"thought": thought_text, "action": action, "tool_call_id": tool_call_id})

            assistant_msg = {
                "role": "assistant",
                "content": accumulated,
                "tool_calls": [{"id": tool_call_id, "type": "function", "function": {"name": action, "arguments": json.dumps(action_input)}}],
            }
            if reasoning_content:
                assistant_msg["reasoning_content"] = reasoning_content
            working_messages.append(assistant_msg)

            yield TurnEvent(type="tool_call", turn=turn, content={"tool": action, "status": "running", "tool_call_id": tool_call_id})

            tool_result = await self.tools.execute(name=action, arguments=action_input, trace_id=trace_id, tenant_id=tenant_id)

            tool_call_count += 1
            seen_tool_calls.add(call_key)
            if action == WEB_SEARCH_TOOL_NAME and tool_result.get("success"):
                web_search_count += 1
                last_web_search_query = str(action_input.get("query", "")).strip()
                last_web_search_result = tool_result
            if action == CVE_CATALOG_TOOL_NAME and tool_result.get("success"):
                last_cve_catalog_result = tool_result
            tool_calls_log.append({"turn": turn, "tool": action, "input": action_input, "output": tool_result})

            if action == WEB_SEARCH_TOOL_NAME and tool_result.get("success"):
                web_search_count += 1
                last_web_search_query = str(action_input.get("query", "")).strip()
                last_web_search_result = tool_result
                relevant_results = _web_search_relevant_results(
                    last_web_search_query,
                    _normalize_web_search_results((tool_result.get("data") or {}).get("results", [])),
                )
                if not relevant_results:
                    fallback = _build_web_search_insufficient(last_web_search_query)
                    for i in range(0, len(fallback), 20):
                        yield TurnEvent(type="answer_token", turn=turn, content=fallback[i:i+20])
                    return

            obs_content = compact_tool_observation(tool_result, self.obs_max_tokens)

            working_messages.append({"role": "tool", "content": obs_content, "tool_call_id": tool_call_id})

            result_content = {
                "tool": action,
                "success": tool_result.get("success"),
                "tool_call_id": tool_call_id,
                "evidence_source": tool_result.get("evidence_source", []),
                "execution_time_ms": tool_result.get("execution_time_ms", 0),
            }
            # RAG transparency: pass retrieval summary to frontend
            if action == "rag_search" and isinstance(tool_result.get("data"), dict):
                rag_data = tool_result["data"]
                results_list = rag_data.get("results", [])
                result_content["rag_summary"] = {
                    "query": rag_data.get("query", ""),
                    "found": rag_data.get("found", False),
                    "result_count": len(results_list),
                    "sources": [r.get("source", r.get("doc_id", "")) for r in results_list[:3]],
                }
            yield TurnEvent(type="tool_result", turn=turn, content=result_content)

            if not tool_result.get("success"):
                consecutive_failures += 1
            else:
                consecutive_failures = 0

        if last_web_search_result is not None:
            fallback = _build_web_search_fallback(last_web_search_query, last_web_search_result)
            for i in range(0, len(fallback), 20):
                yield TurnEvent(type="answer_token", turn=self.max_turns, content=fallback[i:i+20])
            return

        if last_cve_catalog_result is not None:
            fallback = _build_cve_catalog_fallback(last_cve_catalog_result)
            for i in range(0, len(fallback), 20):
                yield TurnEvent(type="answer_token", turn=self.max_turns, content=fallback[i:i+20])
            return

        yield TurnEvent(type="error", turn=self.max_turns, content={"error": "max_turns_reached"})
