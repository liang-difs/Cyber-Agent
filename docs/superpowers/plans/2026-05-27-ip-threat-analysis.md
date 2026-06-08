# IP Threat Analysis Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement an IP threat analysis tool that queries ip-api.com for GeoIP data and AbuseIPDB for threat intelligence, computes a weighted risk score, caches in Redis, and returns structured data for the ReAct Agent.

**Architecture:** The IP tool follows the existing Tool Protocol pattern (ToolInput/ToolResult), matching the IoC and CVE tool structure. It queries ip-api.com (free, no key) for GeoIP and AbuseIPDB (API key required) for abuse reports concurrently via asyncio.gather. The risk score is 70% AbuseIPDB + 30% geo risk adjustment. Graceful degradation when AbuseIPDB is unavailable.

**Tech Stack:** httpx (async HTTP), asyncio.gather (concurrency), Redis (caching), ip-api.com, AbuseIPDB API v2

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `backend/app/tools/ip_tool.py` | Create | IP threat analysis tool |
| `backend/app/core/config.py` | Modify | Add `abuseipdb_api_key` field |
| `backend/app/agent/tool_executor.py` | Modify | Register ip_tool |
| `tests/test_ip_tool.py` | Create | Unit tests |

---

### Task 1: Add `abuseipdb_api_key` to Settings

**Files:**
- Modify: `backend/app/core/config.py`
- Test: `tests/test_config.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_config.py`:

```python
def test_settings_has_abuseipdb_api_key(settings):
    assert hasattr(settings, "abuseipdb_api_key")
    assert isinstance(settings.abuseipdb_api_key, str)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_config.py::test_settings_has_abuseipdb_api_key -v`
Expected: FAIL

- [ ] **Step 3: Add abuseipdb_api_key field**

In `backend/app/core/config.py`, add after `otx_api_key: str = ""`:

```python
    # AbuseIPDB
    abuseipdb_api_key: str = ""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_config.py -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/core/config.py tests/test_config.py
git commit -m "feat: add abuseipdb_api_key to Settings"
```

---

### Task 2: Create IP Threat Analysis Tool — Full Implementation

**Files:**
- Create: `backend/app/tools/ip_tool.py`
- Test: `tests/test_ip_tool.py`

- [ ] **Step 1: Write the tests**

Create `tests/test_ip_tool.py`:

```python
"""Tests for IP Threat Analysis Tool."""

import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.tools.ip_tool import IPThreatTool, IPThreatInput


@pytest.fixture
def tool():
    return IPThreatTool()


def test_tool_properties(tool):
    assert tool.name == "ip_threat_analysis"
    assert tool.version == "v1"


def test_tool_schema(tool):
    schema = tool.get_schema()
    assert schema["function"]["name"] == "ip_threat_analysis"
    params = schema["function"]["parameters"]
    assert "ip" in params["properties"]
    assert "ip" in params["required"]


def test_input_class(tool):
    assert tool.input_class == IPThreatInput


@pytest.mark.anyio
async def test_execute_with_geoip_only(tool):
    """Test with only GeoIP (no AbuseIPDB key)."""
    mock_geo = {
        "status": "success",
        "country": "United States",
        "countryCode": "US",
        "city": "New York",
        "isp": "Google LLC",
        "as": "AS15169 Google LLC",
        "lat": 40.7128,
        "lon": -74.006,
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = mock_geo
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient.get", return_value=mock_response), \
         patch("app.tools.ip_tool.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(
            abuseipdb_api_key="",
            redis_url="",
        )
        mock_settings.cache_clear = MagicMock()
        result = await tool.execute(IPThreatInput(
            ip="8.8.8.8",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is True
    assert result.data["ip"] == "8.8.8.8"
    assert result.data["geo"]["country"] == "United States"
    assert result.data["geo"]["isp"] == "Google LLC"
    assert result.data["risk_score"] == 0
    assert result.data["found"] is True


@pytest.mark.anyio
async def test_execute_with_both_sources(tool):
    """Test with both GeoIP and AbuseIPDB."""
    mock_geo = {
        "status": "success",
        "country": "Russia",
        "countryCode": "RU",
        "city": "Moscow",
        "isp": "Evil Corp",
        "as": "AS12345 Evil Corp",
        "lat": 55.7558,
        "lon": 37.6173,
    }
    mock_abuse = {
        "data": {
            "abuseConfidenceScore": 85,
            "totalReports": 1234,
            "lastReportedAt": "2024-01-15T10:30:00Z",
            "usageType": "Data Center/Web Hosting",
            "isWhitelisted": False,
        }
    }

    call_count = 0

    async def mock_get(url, **kwargs):
        nonlocal call_count
        call_count += 1
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        if "ip-api" in url:
            resp.json.return_value = mock_geo
        else:
            resp.json.return_value = mock_abuse
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get), \
         patch("app.tools.ip_tool.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(
            abuseipdb_api_key="test-key",
            redis_url="",
        )
        mock_settings.cache_clear = MagicMock()
        result = await tool.execute(IPThreatInput(
            ip="1.2.3.4",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is True
    assert result.data["abuse"]["abuse_confidence_score"] == 85
    assert result.data["risk_score"] > 0
    assert result.data["risk_level"] in ["critical", "high", "medium", "low", "safe"]


@pytest.mark.anyio
async def test_execute_with_timeout(tool):
    """Test graceful degradation on timeout."""
    import httpx as httpx_mod

    with patch("httpx.AsyncClient.get", side_effect=httpx_mod.TimeoutException("timeout")), \
         patch("app.tools.ip_tool.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(
            abuseipdb_api_key="test-key",
            redis_url="",
        )
        mock_settings.cache_clear = MagicMock()
        result = await tool.execute(IPThreatInput(
            ip="1.2.3.4",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is False
    assert result.error is not None


@pytest.mark.anyio
async def test_execute_with_cache_hit(tool):
    """Test Redis cache hit."""
    cached_data = json.dumps({
        "ip": "1.2.3.4",
        "geo": {"country": "US"},
        "abuse": {},
        "risk_score": 50,
        "risk_level": "medium",
        "found": True,
    })

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=cached_data)

    with patch("app.tools.ip_tool._get_redis", return_value=mock_redis):
        result = await tool.execute(IPThreatInput(
            ip="1.2.3.4",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is True
    assert result.data["risk_score"] == 50
    assert "cache" in result.evidence_source


def test_risk_level(tool):
    assert tool._risk_level(90) == "critical"
    assert tool._risk_level(70) == "high"
    assert tool._risk_level(50) == "medium"
    assert tool._risk_level(30) == "low"
    assert tool._risk_level(10) == "safe"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_ip_tool.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Implement IP threat tool**

Create `backend/app/tools/ip_tool.py`:

```python
"""IP Threat Analysis Tool — queries ip-api.com and AbuseIPDB.

Follows tool_protocol.md. Returns structured IP data.
No LLM interpretation — Agent layer handles that.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from typing import Any, Optional

import httpx
from pydantic import Field

from app.core.config import get_settings
from app.governance.tool_protocol import ToolInput, ToolResult

IP_API_URL = "http://ip-api.com/json"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
CACHE_TTL = 7200  # 2 hours


class IPThreatInput(ToolInput):
    """IP Threat Analysis input."""

    ip: str = Field(..., description="IPv4 或 IPv6 地址")


class IPThreatTool:
    """查询 GeoIP + AbuseIPDB 获取 IP 威胁分析。"""

    name = "ip_threat_analysis"
    version = "v1"
    input_class = IPThreatInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "ip_threat_analysis",
                "description": "分析 IP 地址的地理位置和威胁情报，返回风险评分。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ip": {
                            "type": "string",
                            "description": "IPv4 或 IPv6 地址",
                        }
                    },
                    "required": ["ip"],
                },
            },
        }

    async def execute(self, input_data: IPThreatInput) -> ToolResult:
        start = time.time()
        ip = input_data.ip.strip()

        # Try cache first
        cached = await self._get_cached(ip)
        if cached:
            return ToolResult(
                success=True,
                tool_name=self.name,
                tool_version=self.version,
                data=cached,
                confidence=1.0,
                evidence_source=["cache", f"redis://ip:{_sha256(ip)}"],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        settings = get_settings()

        # Build queries — GeoIP always, AbuseIPDB if key configured
        tasks = [self._query_geoip(ip)]
        if settings.abuseipdb_api_key:
            tasks.append(self._query_abuseipdb(ip, settings.abuseipdb_api_key))

        try:
            raw_results = await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error=f"Query failed: {str(e)}",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Process results
        geo_data = {}
        abuse_data = {}

        for r in raw_results:
            if isinstance(r, Exception):
                continue
            if r.get("type") == "geoip":
                geo_data = r.get("data", {})
            elif r.get("type") == "abuse":
                abuse_data = r.get("data", {})

        if not geo_data and not abuse_data:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error="All data sources failed",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Compute risk score
        abuse_score = abuse_data.get("abuse_confidence_score", 0)
        risk_score = round(0.70 * abuse_score + 0.30 * 0)  # geo_risk = 0 for now

        result_data = {
            "ip": ip,
            "geo": geo_data,
            "abuse": abuse_data,
            "risk_score": risk_score,
            "risk_level": self._risk_level(risk_score),
            "found": True,
        }

        # Cache result
        await self._set_cached(ip, result_data)

        evidence = []
        if geo_data:
            evidence.append("ip-api.com")
        if abuse_data:
            evidence.append("abuseipdb.com")

        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data=result_data,
            confidence=1.0,
            evidence_source=evidence,
            trace_id=input_data.trace_id,
            execution_time_ms=int((time.time() - start) * 1000),
        )

    async def _query_geoip(self, ip: str) -> dict[str, Any]:
        """Query ip-api.com for GeoIP data."""
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{IP_API_URL}/{ip}",
                params={"fields": "status,message,country,countryCode,city,isp,as,lat,lon"},
            )
            resp.raise_for_status()
            data = resp.json()

        if data.get("status") != "success":
            return {"type": "geoip", "data": {}}

        return {
            "type": "geoip",
            "data": {
                "country": data.get("country", ""),
                "country_code": data.get("countryCode", ""),
                "city": data.get("city", ""),
                "isp": data.get("isp", ""),
                "as": data.get("as", ""),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
            },
        }

    async def _query_abuseipdb(self, ip: str, api_key: str) -> dict[str, Any]:
        """Query AbuseIPDB for threat data."""
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                ABUSEIPDB_URL,
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": api_key, "Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()

        d = data.get("data", {})
        return {
            "type": "abuse",
            "data": {
                "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "last_reported_at": d.get("lastReportedAt", ""),
                "usage_type": d.get("usageType", ""),
                "is_whitelisted": d.get("isWhitelisted", False),
            },
        }

    @staticmethod
    def _risk_level(score: int) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 40:
            return "medium"
        if score >= 20:
            return "low"
        return "safe"

    async def _get_cached(self, ip: str) -> Optional[dict]:
        redis = _get_redis()
        if not redis:
            return None
        try:
            data = await redis.get(f"ip:{_sha256(ip)}")
            if data:
                return json.loads(data)
        except Exception:
            pass
        return None

    async def _set_cached(self, ip: str, data: dict) -> None:
        redis = _get_redis()
        if not redis:
            return
        try:
            await redis.set(
                f"ip:{_sha256(ip)}",
                json.dumps(data, ensure_ascii=False),
                ex=CACHE_TTL,
            )
        except Exception:
            pass


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _get_redis():
    import redis.asyncio as redis
    from app.core.config import get_settings

    settings = get_settings()
    if settings.redis_url:
        return redis.from_url(settings.redis_url)
    return None


ip_tool = IPThreatTool()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_ip_tool.py -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/tools/ip_tool.py tests/test_ip_tool.py
git commit -m "feat: add IP threat analysis tool with GeoIP + AbuseIPDB"
```

---

### Task 3: Register IP Tool in Registry

**Files:**
- Modify: `backend/app/agent/tool_executor.py`

- [ ] **Step 1: Add ip_tool import and registration**

In `backend/app/agent/tool_executor.py`, add:

```python
from app.tools.ip_tool import ip_tool
```

And after `tool_registry.register(ioc_tool)`:

```python
tool_registry.register(ip_tool)
```

- [ ] **Step 2: Run all tests**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/ -v --tb=short`
Expected: ALL PASS

- [ ] **Step 3: Commit**

```bash
git add backend/app/agent/tool_executor.py
git commit -m "feat: register ip_tool in global registry"
```

---

### Task 4: Manual Verification — End-to-End IP Analysis

**Files:**
- None (manual testing)

- [ ] **Step 1: Add AbuseIPDB key to .env**

User adds `ABUSEIPDB_API_KEY=<their-key>` to `.env`

- [ ] **Step 2: Start server and test**

```bash
curl -s -X POST http://localhost:8000/verify/chain \
  -H "Content-Type: application/json" \
  -d '{"message":"请使用 ip_threat_analysis 工具分析 IP 8.8.8.8"}'
```

Expected:
- `tool_results[0].tool_name` == "ip_threat_analysis"
- `tool_results[0].success` == true
- `tool_results[0].data.geo.country` has value
- `steps.6_final_response` contains Chinese analysis
