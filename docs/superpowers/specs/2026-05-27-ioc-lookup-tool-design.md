# IoC Threat Intelligence Lookup Tool — Design Spec

## Overview

IoC (Indicator of Compromise) 查询工具，通过并发查询 OTX AlienVault 和 VirusTotal 两个威胁情报源，返回归一化的威胁评分和结构化数据。遵循 Tool Protocol，不做 LLM 解释。

## Data Sources

| 数据源 | 查询对象 | 免费限额 | 缓存 TTL | 权重 |
|--------|----------|----------|----------|------|
| OTX AlienVault | IP / Domain / Hash / URL | 无限（注册） | 1 小时 | 0.50 |
| VirusTotal | IP / Domain / Hash / URL | 4 次/分钟 | 1 小时 | 0.50 |

- 未配置 API Key 的源自动跳过，不报错
- 超时 10s 的源降级，返回空结果
- 权重在配置中可调

## API Endpoints

### OTX AlienVault
- Base: `https://otx.alienvault.com/api/v1`
- IP: `GET /indicators/ipv4/{value}/general`
- Domain: `GET /indicators/domain/{value}/general`
- Hash: `GET /indicators/file/{value}/general`
- URL: `GET /indicators/url/{value}/general`
- Auth: `X-OTX-API-KEY` header

### VirusTotal
- Base: `https://www.virustotal.com/api/v3`
- IP: `GET /ip_addresses/{value}`
- Domain: `GET /domains/{value}`
- Hash: `GET /files/{value}`
- URL: `GET /urls/{url_id}` (base64 of URL)
- Auth: `x-apikey` header

## Input

```python
class IoCInput(ToolInput):
    value: str = Field(..., description="IoC 值，如 IP、域名、Hash、URL")
    type: str = Field(default="auto", description="IoC 类型: ip, domain, hash, url, auto")
```

Type auto-detection rules:
- IPv4/IPv6 pattern → `ip`
- Contains `://` → `url`
- 64-char hex → `hash` (SHA256)
- Otherwise → `domain`

## Output

```python
{
    "ioc_value": "1.2.3.4",
    "ioc_type": "ip",
    "risk_score": 72,          # 0-100 weighted average
    "risk_level": "high",       # critical/high/medium/low/safe
    "sources": [
        {
            "source": "otx",
            "score": 80,
            "tags": ["malware", "botnet"],
            "raw": { ... }
        },
        {
            "source": "virustotal",
            "score": 65,
            "tags": ["malicious"],
            "raw": { ... }
        }
    ],
    "found": true
}
```

Risk level mapping:
- 80-100: critical
- 60-79: high
- 40-59: medium
- 20-39: low
- 0-19: safe

## Score Normalization

### OTX
OTX returns `pulse_info.count` (number of threat reports mentioning this IoC) and reputation data.
- pulse_count >= 10 → score 90
- pulse_count 5-9 → score 70
- pulse_count 1-4 → score 50
- pulse_count 0 → score 10

### VirusTotal
VT returns `last_analysis_stats` with `malicious`, `suspicious`, `undetected`, etc.
- score = (malicious / total_engines) * 100

## Caching

- Key: `ioc:{type}:{value_sha256}`
- TTL: 3600s (1 hour)
- Cache on successful query only

## Concurrency

```python
results = await asyncio.gather(
    self._query_otx(ioc_type, value),
    self._query_vt(ioc_type, value),
    return_exceptions=True
)
```

Each source query wrapped in try/except — exceptions produce empty result, not tool failure.

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `backend/app/tools/ioc_tool.py` | Create | IoC lookup tool |
| `backend/app/core/config.py` | Modify | Add `otx_api_key` field |
| `backend/app/agent/tool_executor.py` | Modify | Register ioc_tool |
| `tests/test_ioc_tool.py` | Create | Unit tests |

## Constraints

- Tool only returns data — no LLM interpretation
- Follows Tool Protocol (ToolInput/ToolResult)
- Python 3.9 compatible (`from __future__ import annotations`)
- All sources queried concurrently, individual timeout 10s
- Graceful degradation when sources unavailable
