# Cost Metrics

> 成本相关指标定义。

## 指标列表

### 每次调用成本
- **名称**: `llm_cost_per_call`
- **定义**: 基于 token 使用量计算的单次调用成本
- **采集点**: `llm/router.py`
- **计算**: `input_tokens * input_price + output_tokens * output_price`

### 每日总成本
- **名称**: `daily_total_cost`
- **定义**: 当天所有 LLM 调用的总成本
- **采集点**: 聚合计算

### 每用户成本
- **名称**: `cost_per_tenant`
- **定义**: 每个租户的 LLM 调用成本
- **采集点**: 按 tenant_id 聚合

### Tool 调用成本
- **名称**: `tool_call_cost`
- **定义**: 每次 Tool 调用的外部 API 成本
- **采集点**: 每个 Tool（如有外部 API 调用）

## 成本优化策略

### Prompt Caching
- 目标: 减少重复 prompt 的 token 消耗
- 监控: `llm_cache_hit_rate`

### 模型降级
- 策略: 简单查询使用小模型，复杂查询使用大模型
- 监控: 按模型的调用分布

### 批处理
- 策略: 非实时任务使用 batch API
- 监控: batch vs realtime 的成本对比

## 采集方式

```python
from prometheus_client import Counter

llm_cost = Counter('llm_cost_dollars', 'LLM cost in dollars', ['model', 'tenant_id'])
```

## 告警规则

| 指标 | 阈值 | 等级 |
|------|------|------|
| 日成本超预算 120% | P1 | 立即通知 |
| 单用户成本异常高 | P2 | 1小时内处理 |
