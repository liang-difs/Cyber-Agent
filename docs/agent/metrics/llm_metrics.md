# LLM Metrics

> LLM 调用相关指标定义。

## 指标列表

### 调用成功率
- **名称**: `llm_call_success_rate`
- **定义**: 成功调用次数 / 总调用次数
- **目标**: >= 99.5%
- **采集点**: `llm/router.py`

### 调用延迟
- **名称**: `llm_call_latency_ms`
- **定义**: 从发送请求到收到完整响应的时间
- **目标**: P50 < 2s, P99 < 10s
- **采集点**: `llm/router.py`

### Token 使用量
- **名称**: `llm_token_usage`
- **定义**: 每次调用的 input/output token 数
- **采集点**: `llm/router.py`
- **用途**: 成本监控

### Fallback 触发率
- **名称**: `llm_fallback_rate`
- **定义**: 触发 fallback 的调用次数 / 总调用次数
- **目标**: < 1%
- **采集点**: `llm/router.py`

### Prompt Cache 命中率
- **名称**: `llm_cache_hit_rate`
- **定义**: 命中缓存的调用次数 / 总调用次数
- **目标**: > 60%
- **采集点**: `llm/router.py`

## 采集方式

```python
from prometheus_client import Counter, Histogram

llm_calls = Counter('llm_calls_total', 'Total LLM calls', ['model', 'status'])
llm_latency = Histogram('llm_call_latency_seconds', 'LLM call latency', ['model'])
llm_tokens = Counter('llm_tokens_total', 'Total tokens used', ['model', 'type'])
```

## 告警规则

| 指标 | 阈值 | 等级 |
|------|------|------|
| 成功率 < 99% | P1 | 立即通知 |
| P99 延迟 > 15s | P2 | 1小时内处理 |
| Fallback 率 > 5% | P1 | 立即通知 |
