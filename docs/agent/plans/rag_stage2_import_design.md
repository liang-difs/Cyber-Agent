# RAG Stage 2 Import Design

> 目标：在已完成 NVD CVE 全量导入的基础上，分阶段接入 ATT&CK、Sigma、威胁情报、工具文档和内部事件历史，形成统一、可回滚、可验证的 RAG 导入方案。

## 1. 当前基线

- 已完成：NVD CVE 语料导入到 BM25 + ChromaDB。
- 当前数量：44,165 条唯一 CVE。
- 当前限制：导入链路只覆盖 CVE，不覆盖 ATT&CK / Sigma / threat intel / internal history / tool docs。
- 已存在的处理结果：`corpus/processed/manifest.json`、`normalized_docs.jsonl`、`chunks.jsonl`。

## 2. 第二阶段目标

把仓库里已经具备的知识资产接入 RAG，并明确公共知识库与租户私有知识库的边界：

- 公共知识库：CVE、ATT&CK、Sigma、威胁情报、工具文档。
- 租户私有知识库：内部事件历史、人工复核结论、客户定制分析。
- 检索策略：公共库优先，租户库补充，最终 RRF 融合。

## 3. 推荐导入顺序

### Stage 2.1: ATT&CK + Sigma

优先原因：

- 直接服务告警研判、攻击链分析、处置建议。
- 与现有 `analysis/attack_chain.py`、`analysis/correlation.py`、`alerts` 流程强相关。
- 文档量相对可控，容易做质量验收。

### Stage 2.2: 威胁情报

包含：

- `attack/intel_norm/`
- `attack/intel_raw/`
- `kev.csv`
- `epss_subset.json`
- `vendor_advisories.jsonl`

用途：

- 增强 CVE 风险解释。
- 给告警和 IOC 研判补充背景。

### Stage 2.3: 安全工具文档

包含：

- `protocol/rfc/`
- 后续可扩展到 Suricata / Zeek / YARA 文档。

用途：

- 提升协议、流量、规则解释能力。
- 支持用户问“这个字段/规则是什么意思”。

### Stage 2.4: 内部事件历史

建议最后接入。

原因：

- 需要租户隔离。
- 需要人工脱敏和质量校验。
- 适合在公共库稳定后再做。

## 4. 数据分层设计

### 4.1 公共库

公共库统一前缀：`kb_public_`

建议 collection：

- `kb_public_cve`
- `kb_public_attack`
- `kb_public_sigma`
- `kb_public_threat_intel`
- `kb_public_tool_docs`

### 4.2 租户私有库

统一前缀：`kb_tenant_{tenant_id}_`

建议 collection：

- `kb_tenant_{tenant_id}_events`
- `kb_tenant_{tenant_id}_reviews`

原则：

- 任何内部事件历史不得进入公共库。
- 所有租户库必须强制 tenant_id 过滤。

## 5. 文档规范

统一每条文档的最小字段：

- `doc_id`
- `source_type`
- `category`
- `title`
- `content`
- `tags`
- `tenant_id`
- `source_uri`
- `updated_at`
- `embedding_version`

不同 source_type 的可选字段：

- CVE：`cve_id`, `cvss_score`, `severity`, `published`
- ATT&CK：`attack_id`, `tactic`, `platform`, `procedure_examples`
- Sigma：`rule_id`, `logsource`, `level`, `falsepositives`
- Threat intel：`indicator_type`, `confidence`, `campaign`, `actor`
- Tool docs：`product`, `version`, `section`
- Internal history：`incident_id`, `analyst`, `verdict`, `summary`

## 6. 导入流水线

建议拆成四步：

1. Normalize：把原始文件转成统一文档结构。
2. Chunk：按 source_type 使用不同分块策略。
3. Index：写入公共库或租户库。
4. Verify：抽样检索、统计覆盖率、重复 ID 检查。

### 分块建议

- CVE：一条 CVE 一个 chunk。
- ATT&CK：一个 Technique 一个 chunk。
- Sigma：一条规则加解释一个 chunk。
- Threat intel：500 token 左右语义段落。
- Tool docs：按标题 + 段落切分。
- Internal history：每次事件分析一个 chunk，必要时附 summary。

## 7. 检索设计

### 公共检索

- 向量检索：ChromaDB / Milvus。
- 关键词检索：BM25。
- 融合：RRF。

### 私有检索

- 只查当前租户 collection。
- 私有结果与公共结果合并后再 RRF。

### 结果排序

推荐顺序：

1. 精确匹配结果。
2. 当前租户私有结果。
3. 公共知识库结果。

## 8. 验收标准

第二阶段每个子域都要满足：

- 导入可重复。
- 结果可统计。
- 失败可回滚。
- 关键查询可命中。
- 不引入跨租户泄露。

建议验收样例：

- 输入 `CVE-2024-3400`，能命中 CVE 库并返回解释。
- 输入 ATT&CK 技术名，能命中对应 technique 文档。
- 输入 Sigma 规则关键字，能命中规则解释。
- 输入已知 IP / ASN / KEV 关键词，能命中 threat intel。
- 租户 A 查询租户 B 事件，结果为空。

## 9. 风险与对策

- 风险：语料重复和 ID 冲突。
  - 对策：导入前做 doc_id 去重。
- 风险：大型集合导入耗时过长。
  - 对策：按 source_type 分批、可断点续跑。
- 风险：内部事件误入公共库。
  - 对策：在 normalize 阶段强制检查 tenant_id。
- 风险：嵌入模型/向量库变更导致重建。
  - 对策：记录 `embedding_version`，必要时整库重建。

## 10. 建议执行顺序

1. 先做 ATT&CK + Sigma。
2. 再做 threat intel。
3. 然后做 tool docs。
4. 最后做 tenant 私有事件历史。
