# Tool Metrics

> Tool 调用相关指标定义。

## 指标列表

### Tool 调用成功率
- **名称**: `tool_call_success_rate`
- **定义**: 成功调用次数 / 总调用次数
- **目标**: >= 98%
- **采集点**: Tool Registry

### Tool 调用延迟
- **名称**: `tool_call_latency_ms`
- **定义**: Tool 执行时间
- **目标**: P50 < 500ms, P99 < 5s
- **采集点**: 每个 Tool

### Tool 重试率
- **名称**: `tool_retry_rate`
- **定义**: 重试次数 / 总调用次数
- **目标**: < 2%
- **采集点**: Tool Registry

### Tool 超时率
- **名称**: `tool_timeout_rate`
- **定义**: 超时次数 / 总调用次数
- **目标**: < 1%
- **采集点**: Tool Registry

### Hallucination Rate
- **名称**: `tool_hallucination_rate`
- **定义**: 编造结果的次数 / 总调用次数
- **目标**: < 2%
- **采集点**: 需要人工标注或自动检测

### Tool Confidence 分布
- **名称**: `tool_confidence_distribution`
- **定义**: Tool 返回的 confidence 值分布
- **采集点**: Tool Registry

## 采集方式

```python
from prometheus_client import Counter, Histogram, Summary

tool_calls = Counter('tool_calls_total', 'Total tool calls', ['tool', 'status'])
tool_latency = Histogram('tool_call_latency_seconds', 'Tool call latency', ['tool'])
tool_confidence = Summary('tool_confidence', 'Tool confidence scores', ['tool'])
```

## 告警规则

| 指标 | 阈值 | 等级 |
|------|------|------|
| 成功率 < 95% | P1 | 立即通知 |
| 超时率 > 5% | P1 | 立即通知 |
| 重试率 > 10% | P2 | 1小时内处理 |
