# IP Threat Analysis Tool — Design Spec

## Overview

IP 地址威胁分析工具，通过查询 ip-api.com（GeoIP）和 AbuseIPDB（威胁情报）获取 IP 的地理位置、ASN/ISP 和威胁评分。遵循 Tool Protocol，不做 LLM 解释。

## Data Sources

| 数据源 | 查询内容 | 免费限额 | 缓存 TTL | 权重 |
|--------|----------|----------|----------|------|
| ip-api.com | 国家、城市、ISP、ASN、经纬度 | 45次/分钟，HTTP only | 2 小时 | GeoIP 辅助 |
| AbuseIPDB | abuseConfidenceScore, reportCount, usageType | 1000次/天 | 2 小时 | 0.70 |

- ip-api.com 仅支持 HTTP（非 HTTPS），用于 GeoIP 信息
- AbuseIPDB 需要 API Key（用户自行配置到 .env）
- 无 AbuseIPDB Key 时降级：只返回 GeoIP 数据，risk_score = 0

## Input

```python
class IPThreatInput(ToolInput):
    ip: str = Field(..., description="IPv4 或 IPv6 地址")
```

## Output

```json
{
    "ip": "1.2.3.4",
    "geo": {
        "country": "United States",
        "country_code": "US",
        "city": "New York",
        "isp": "Example ISP",
        "as": "AS12345 Example Corp",
        "lat": 40.7128,
        "lon": -74.0060
    },
    "abuse": {
        "abuse_confidence_score": 85,
        "total_reports": 1234,
        "last_reported_at": "2024-01-15T10:30:00Z",
        "usage_type": "Data Center/Web Hosting",
        "is_whitelisted": false
    },
    "risk_score": 60,
    "risk_level": "high",
    "found": true
}
```

Risk level mapping (same as IoC tool):
- 80-100: critical
- 60-79: high
- 40-59: medium
- 20-39: low
- 0-19: safe

## Score Model

```
risk_score = 0.70 × abuse_confidence_score + 0.30 × geo_risk_adjustment
```

geo_risk_adjustment: 0 by default, can add risk points for certain countries/regions if needed in future.

Without AbuseIPDB: risk_score = 0, geo data still returned.

## API Endpoints

### ip-api.com
- `GET http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,isp,as,lat,lon`
- No API key needed
- HTTP only (no HTTPS on free tier)

### AbuseIPDB
- `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90`
- Header: `Key: {api_key}`, `Accept: application/json`

## Caching

- Key: `ip:{sha256(ip)}`
- TTL: 7200s (2 hours)

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `backend/app/tools/ip_tool.py` | Create | IP threat analysis tool |
| `backend/app/core/config.py` | Modify | Add `abuseipdb_api_key` field |
| `backend/app/agent/tool_executor.py` | Modify | Register ip_tool |
| `tests/test_ip_tool.py` | Create | Unit tests |

## Constraints

- Tool only returns data — no LLM interpretation
- Follows Tool Protocol (ToolInput/ToolResult)
- Python 3.9 compatible (`from __future__ import annotations`)
- ip-api.com is HTTP only — acceptable for Phase 2
- Graceful degradation when AbuseIPDB unavailable
