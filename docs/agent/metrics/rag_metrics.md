# RAG Metrics

> RAG 检索相关指标定义。

## 指标列表

### 检索命中率
- **名称**: `rag_retrieval_hit_rate`
- **定义**: 检索到相关文档的查询次数 / 总查询次数
- **目标**: >= 85%
- **采集点**: RAG Engine

### 检索延迟
- **名称**: `rag_retrieval_latency_ms`
- **定义**: 从查询到返回结果的时间
- **目标**: P50 < 200ms, P99 < 1s
- **采集点**: RAG Engine

### Rerank 质量
- **名称**: `rag_rerank_quality`
- **定义**: Rerank 后的排序与人工标注的相关性
- **目标**: NDCG@10 >= 0.7
- **采集点**: RAG Engine

### Context 相关性
- **名称**: `rag_context_relevance`
- **定义**: 检索到的文档与查询的相关性评分
- **目标**: 平均分 >= 0.75
- **采集点**: 需要评估 pipeline

### Chunk 覆盖率
- **名称**: `rag_chunk_coverage`
- **定义**: 被检索到的 chunk 数 / 总 chunk 数
- **用途**: 评估索引质量
- **采集点**: RAG Engine

## 采集方式

```python
from prometheus_client import Counter, Histogram

rag_queries = Counter('rag_queries_total', 'Total RAG queries', ['status'])
rag_latency = Histogram('rag_retrieval_latency_seconds', 'RAG retrieval latency')
rag_hits = Counter('rag_hits_total', 'RAG retrieval hits')
```

## 告警规则

| 指标 | 阈值 | 等级 |
|------|------|------|
| 命中率 < 80% | P2 | 1小时内处理 |
| P99 延迟 > 2s | P2 | 1小时内处理 |
