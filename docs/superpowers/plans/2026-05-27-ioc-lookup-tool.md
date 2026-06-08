# IoC Lookup Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement an IoC (Indicator of Compromise) lookup tool that queries OTX AlienVault and VirusTotal concurrently, normalizes threat scores, caches in Redis, and returns structured threat data for the ReAct Agent.

**Architecture:** The IoC tool follows the existing Tool Protocol pattern (ToolInput/ToolResult), matching the CVE tool's structure. It queries two threat intelligence APIs concurrently via asyncio.gather, normalizes each source's score to 0-100, computes a weighted average, and caches results in Redis. The tool auto-detects IoC type (ip/domain/hash/url) and gracefully degrades when sources are unavailable.

**Tech Stack:** httpx (async HTTP), asyncio.gather (concurrency), Redis (caching), OTX API v1, VirusTotal API v3

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `backend/app/tools/ioc_tool.py` | Create | IoC lookup tool — type detection, OTX/VT queries, score normalization, caching |
| `backend/app/core/config.py` | Modify | Add `otx_api_key` field to Settings |
| `backend/app/agent/tool_executor.py` | Modify | Register ioc_tool in global registry |
| `tests/test_ioc_tool.py` | Create | Unit tests for IoC tool |

---

### Task 1: Add `otx_api_key` to Settings

**Files:**
- Modify: `backend/app/core/config.py:11-22`
- Test: `tests/test_config.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_config.py`:

```python
def test_settings_has_otx_api_key(settings):
    assert hasattr(settings, "otx_api_key")
    assert isinstance(settings.otx_api_key, str)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_config.py::test_settings_has_otx_api_key -v`
Expected: FAIL — Settings has no `otx_api_key` attribute

- [ ] **Step 3: Add otx_api_key field**

In `backend/app/core/config.py`, add after line 18 (`nvd_api_key: str = ""`):

```python
    # OTX AlienVault
    otx_api_key: str = ""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_config.py -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/core/config.py tests/test_config.py
git commit -m "feat: add otx_api_key to Settings"
```

---

### Task 2: Create IoC Tool — Type Detection and Schema

**Files:**
- Create: `backend/app/tools/ioc_tool.py`
- Test: `tests/test_ioc_tool.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_ioc_tool.py`:

```python
"""Tests for IoC Lookup Tool."""

import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.tools.ioc_tool import IoCLookupTool, IoCInput, detect_ioc_type


@pytest.fixture
def tool():
    return IoCLookupTool()


def test_tool_properties(tool):
    assert tool.name == "ioc_lookup"
    assert tool.version == "v1"


def test_tool_schema(tool):
    schema = tool.get_schema()
    assert schema["function"]["name"] == "ioc_lookup"
    params = schema["function"]["parameters"]
    assert "value" in params["properties"]
    assert "value" in params["required"]
    assert "type" in params["properties"]


def test_input_class(tool):
    assert tool.input_class == IoCInput


def test_detect_type_ip():
    assert detect_ioc_type("192.168.1.1") == "ip"
    assert detect_ioc_type("8.8.8.8") == "ip"
    assert detect_ioc_type("2001:db8::1") == "ip"


def test_detect_type_domain():
    assert detect_ioc_type("evil.example.com") == "domain"
    assert detect_ioc_type("malware.org") == "domain"


def test_detect_type_hash():
    assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"  # MD5
    assert detect_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "hash"  # SHA256


def test_detect_type_url():
    assert detect_ioc_type("https://evil.example.com/malware") == "url"
    assert detect_ioc_type("http://192.168.1.1/payload") == "url"


def test_detect_type_explicit():
    """Explicit type overrides auto-detection."""
    assert detect_ioc_type("192.168.1.1", explicit_type="ip") == "ip"
    assert detect_ioc_type("evil.com", explicit_type="domain") == "domain"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_ioc_tool.py -v`
Expected: FAIL — module `app.tools.ioc_tool` not found

- [ ] **Step 3: Implement IoC tool skeleton with type detection**

Create `backend/app/tools/ioc_tool.py`:

```python
"""IoC Lookup Tool — queries OTX AlienVault and VirusTotal for threat intelligence.

Follows tool_protocol.md. Returns structured IoC data.
No LLM interpretation — Agent layer handles that.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any, Optional

import httpx
from pydantic import Field

from app.core.config import get_settings
from app.governance.tool_protocol import ToolInput, ToolResult

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
VT_BASE_URL = "https://www.virustotal.com/api/v3"
CACHE_TTL = 3600  # 1 hour

# IoC type to OTX/VT path segment mapping
OTX_TYPE_MAP = {
    "ip": "IPv4",
    "domain": "domain",
    "hash": "file",
    "url": "url",
}

VT_TYPE_MAP = {
    "ip": "ip_addresses",
    "domain": "domains",
    "hash": "files",
    "url": "urls",
}


def detect_ioc_type(value: str, explicit_type: str = "auto") -> str:
    """Detect IoC type from value string."""
    if explicit_type != "auto":
        return explicit_type

    value = value.strip()

    # IPv4
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
        return "ip"

    # IPv6 (simplified check)
    if ":" in value and re.match(r"^[0-9a-fA-F:]+$", value):
        return "ip"

    # URL
    if "://" in value:
        return "url"

    # Hash (MD5=32, SHA1=40, SHA256=64 hex chars)
    if re.match(r"^[0-9a-fA-F]{32}$", value) or \
       re.match(r"^[0-9a-fA-F]{40}$", value) or \
       re.match(r"^[0-9a-fA-F]{64}$", value):
        return "hash"

    # Default to domain
    return "domain"


class IoCInput(ToolInput):
    """IoC Tool input."""

    value: str = Field(..., description="IoC 值，如 IP、域名、Hash、URL")
    type: str = Field(default="auto", description="IoC 类型: ip, domain, hash, url, auto")


class IoCLookupTool:
    """查询 OTX + VirusTotal 获取 IoC 威胁情报。"""

    name = "ioc_lookup"
    version = "v1"
    input_class = IoCInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "ioc_lookup",
                "description": "查询 IoC（IP/域名/Hash/URL）的威胁情报，返回风险评分、标签和多源数据。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "value": {
                            "type": "string",
                            "description": "IoC 值，如 1.2.3.4、evil.com、文件哈希、URL",
                        },
                        "type": {
                            "type": "string",
                            "description": "IoC 类型: ip, domain, hash, url。默认自动检测。",
                            "enum": ["ip", "domain", "hash", "url", "auto"],
                        },
                    },
                    "required": ["value"],
                },
            },
        }

    async def execute(self, input_data: IoCInput) -> ToolResult:
        raise NotImplementedError("Subclass must implement this")


def _get_redis():
    """Get Redis client (lazy init)."""
    import redis.asyncio as redis
    from app.core.config import get_settings

    settings = get_settings()
    if settings.redis_url:
        return redis.from_url(settings.redis_url)
    return None


ioc_tool = IoCLookupTool()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_ioc_tool.py -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/tools/ioc_tool.py tests/test_ioc_tool.py
git commit -m "feat: add IoC tool skeleton with type detection"
```

---

### Task 3: Implement OTX and VirusTotal Query + Score Normalization

**Files:**
- Modify: `backend/app/tools/ioc_tool.py`
- Test: `tests/test_ioc_tool.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_ioc_tool.py`:

```python
@pytest.mark.anyio
async def test_execute_with_otx_only(tool):
    """Test with only OTX configured (VT key empty)."""
    mock_otx_response = {
        "pulse_info": {"count": 5, "pulses": [{"name": "Malware C2", "tags": ["botnet"]}]},
        "reputation": 0,
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = mock_otx_response
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient.get", return_value=mock_response), \
         patch("app.tools.ioc_tool.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(
            otx_api_key="test-otx-key",
            vt_api_key="",
            redis_url="",
        )
        mock_settings.cache_clear = MagicMock()
        result = await tool.execute(IoCInput(
            value="1.2.3.4",
            type="ip",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is True
    assert result.data["ioc_value"] == "1.2.3.4"
    assert result.data["ioc_type"] == "ip"
    assert result.data["found"] is True
    assert len(result.data["sources"]) == 1
    assert result.data["sources"][0]["source"] == "otx"
    assert result.data["risk_score"] > 0


@pytest.mark.anyio
async def test_execute_with_both_sources(tool):
    """Test with both OTX and VT configured."""
    mock_otx = {
        "pulse_info": {"count": 10, "pulses": [{"name": "APT28", "tags": ["apt"]}]},
        "reputation": 0,
    }
    mock_vt = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 45,
                    "suspicious": 5,
                    "undetected": 50,
                    "harmless": 0,
                }
            }
        }
    }

    call_count = 0

    async def mock_get(url, **kwargs):
        nonlocal call_count
        call_count += 1
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        if "alienvault" in url:
            resp.json.return_value = mock_otx
        else:
            resp.json.return_value = mock_vt
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get), \
         patch("app.tools.ioc_tool.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(
            otx_api_key="test-otx-key",
            vt_api_key="test-vt-key",
            redis_url="",
        )
        mock_settings.cache_clear = MagicMock()
        result = await tool.execute(IoCInput(
            value="1.2.3.4",
            type="ip",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is True
    assert len(result.data["sources"]) == 2
    assert result.data["risk_score"] > 0
    sources = {s["source"]: s for s in result.data["sources"]}
    assert "otx" in sources
    assert "virustotal" in sources


@pytest.mark.anyio
async def test_execute_with_timeout(tool):
    """Test graceful degradation when source times out."""
    with patch("httpx.AsyncClient.get", side_effect=httpx.TimeoutException("timeout")), \
         patch("app.tools.ioc_tool.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(
            otx_api_key="test-key",
            vt_api_key="test-key",
            redis_url="",
        )
        mock_settings.cache_clear = MagicMock()
        result = await tool.execute(IoCInput(
            value="1.2.3.4",
            type="ip",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is True
    assert result.data["found"] is False
    assert result.data["risk_score"] == 0


@pytest.mark.anyio
async def test_execute_with_cache_hit(tool):
    """Test Redis cache hit."""
    cached_data = json.dumps({
        "ioc_value": "1.2.3.4",
        "ioc_type": "ip",
        "risk_score": 72,
        "risk_level": "high",
        "sources": [{"source": "otx", "score": 72, "tags": [], "raw": {}}],
        "found": True,
    })

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=cached_data)

    with patch("app.tools.ioc_tool._get_redis", return_value=mock_redis):
        result = await tool.execute(IoCInput(
            value="1.2.3.4",
            type="ip",
            tenant_id="test",
            trace_id="test-trace",
        ))

    assert result.success is True
    assert result.data["risk_score"] == 72
    assert "cache" in result.evidence_source


def test_risk_level_mapping(tool):
    """Test risk level thresholds."""
    assert tool._risk_level(90) == "critical"
    assert tool._risk_level(70) == "high"
    assert tool._risk_level(50) == "medium"
    assert tool._risk_level(30) == "low"
    assert tool._risk_level(10) == "safe"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_ioc_tool.py -v`
Expected: FAIL — `execute` raises NotImplementedError, `_risk_level` not found

- [ ] **Step 3: Implement execute, query methods, and score normalization**

Replace the `IoCLookupTool` class in `backend/app/tools/ioc_tool.py` (keep imports, constants, `detect_ioc_type`, `IoCInput`, and `_get_redis` unchanged):

```python
class IoCLookupTool:
    """查询 OTX + VirusTotal 获取 IoC 威胁情报。"""

    name = "ioc_lookup"
    version = "v1"
    input_class = IoCInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "ioc_lookup",
                "description": "查询 IoC（IP/域名/Hash/URL）的威胁情报，返回风险评分、标签和多源数据。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "value": {
                            "type": "string",
                            "description": "IoC 值，如 1.2.3.4、evil.com、文件哈希、URL",
                        },
                        "type": {
                            "type": "string",
                            "description": "IoC 类型: ip, domain, hash, url。默认自动检测。",
                            "enum": ["ip", "domain", "hash", "url", "auto"],
                        },
                    },
                    "required": ["value"],
                },
            },
        }

    async def execute(self, input_data: IoCInput) -> ToolResult:
        start = time.time()
        ioc_type = detect_ioc_type(input_data.value, input_data.type)
        value = input_data.value.strip()

        # Try cache first
        cached = await self._get_cached(ioc_type, value)
        if cached:
            return ToolResult(
                success=True,
                tool_name=self.name,
                tool_version=self.version,
                data=cached,
                confidence=1.0,
                evidence_source=["cache", f"redis://ioc:{ioc_type}:{_sha256(value)}"],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        settings = get_settings()

        # Build source queries
        tasks = []
        if settings.otx_api_key:
            tasks.append(self._query_otx(ioc_type, value, settings.otx_api_key))
        if settings.vt_api_key:
            tasks.append(self._query_vt(ioc_type, value, settings.vt_api_key))

        if not tasks:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error="No API keys configured (OTX_API_KEY, VT_API_KEY)",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Concurrent query
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        sources = []
        for r in raw_results:
            if isinstance(r, Exception):
                continue
            if r and r.get("found"):
                sources.append(r)

        if not sources:
            result_data = {
                "ioc_value": value,
                "ioc_type": ioc_type,
                "risk_score": 0,
                "risk_level": "safe",
                "sources": [],
                "found": False,
            }
        else:
            # Weighted average
            weights = {"otx": 0.5, "virustotal": 0.5}
            total_weight = sum(weights.get(s["source"], 0.5) for s in sources)
            risk_score = sum(
                s["score"] * weights.get(s["source"], 0.5) for s in sources
            ) / total_weight if total_weight > 0 else 0
            risk_score = round(risk_score)

            result_data = {
                "ioc_value": value,
                "ioc_type": ioc_type,
                "risk_score": risk_score,
                "risk_level": self._risk_level(risk_score),
                "sources": sources,
                "found": True,
            }

        # Cache result
        await self._set_cached(ioc_type, value, result_data)

        evidence = [s["source"] for s in sources]
        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data=result_data,
            confidence=1.0 if sources else 0.0,
            evidence_source=evidence if evidence else [],
            trace_id=input_data.trace_id,
            execution_time_ms=int((time.time() - start) * 1000),
        )

    async def _query_otx(self, ioc_type: str, value: str, api_key: str) -> dict[str, Any]:
        """Query OTX AlienVault API."""
        otx_type = OTX_TYPE_MAP.get(ioc_type, "IPv4")
        url = f"{OTX_BASE_URL}/indicators/{otx_type}/{value}/general"

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers={"X-OTX-API-KEY": api_key})
            resp.raise_for_status()
            data = resp.json()

        pulse_count = data.get("pulse_info", {}).get("count", 0)
        pulses = data.get("pulse_info", {}).get("pulses", [])
        tags = list({t for p in pulses for t in p.get("tags", [])})[:10]

        score = self._otx_score(pulse_count)

        return {
            "source": "otx",
            "score": score,
            "tags": tags,
            "raw": data,
            "found": pulse_count > 0,
        }

    async def _query_vt(self, ioc_type: str, value: str, api_key: str) -> dict[str, Any]:
        """Query VirusTotal API."""
        vt_type = VT_TYPE_MAP.get(ioc_type, "files")

        # VT URL type needs base64 encoding (without padding)
        if ioc_type == "url":
            import base64
            value = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")

        url = f"{VT_BASE_URL}/{vt_type}/{value}"

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers={"x-apikey": api_key})
            resp.raise_for_status()
            data = resp.json()

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 1

        score = round((malicious + suspicious * 0.5) / total * 100) if total > 0 else 0
        score = min(score, 100)

        tags = []
        if malicious > 0:
            tags.append("malicious")
        if suspicious > 0:
            tags.append("suspicious")

        return {
            "source": "virustotal",
            "score": score,
            "tags": tags,
            "raw": data,
            "found": malicious > 0 or suspicious > 0,
        }

    @staticmethod
    def _otx_score(pulse_count: int) -> int:
        """Convert OTX pulse count to 0-100 score."""
        if pulse_count >= 10:
            return 90
        if pulse_count >= 5:
            return 70
        if pulse_count >= 1:
            return 50
        return 10

    @staticmethod
    def _risk_level(score: int) -> str:
        """Map score to risk level."""
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 40:
            return "medium"
        if score >= 20:
            return "low"
        return "safe"

    async def _get_cached(self, ioc_type: str, value: str) -> Optional[dict]:
        """Get from Redis cache."""
        redis = _get_redis()
        if not redis:
            return None
        try:
            data = await redis.get(f"ioc:{ioc_type}:{_sha256(value)}")
            if data:
                return json.loads(data)
        except Exception:
            pass
        return None

    async def _set_cached(self, ioc_type: str, value: str, data: dict) -> None:
        """Set Redis cache."""
        redis = _get_redis()
        if not redis:
            return
        try:
            await redis.set(
                f"ioc:{ioc_type}:{_sha256(value)}",
                json.dumps(data, ensure_ascii=False),
                ex=CACHE_TTL,
            )
        except Exception:
            pass
```

Also add `import asyncio` at the top of the file (after the existing imports) and add this helper function before the class:

```python
def _sha256(value: str) -> str:
    """Return SHA256 hex digest of value."""
    return hashlib.sha256(value.encode()).hexdigest()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/test_ioc_tool.py -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/tools/ioc_tool.py tests/test_ioc_tool.py
git commit -m "feat: implement IoC tool OTX/VT queries with score normalization"
```

---

### Task 4: Register IoC Tool in Registry

**Files:**
- Modify: `backend/app/agent/tool_executor.py`

- [ ] **Step 1: Add ioc_tool import and registration**

In `backend/app/agent/tool_executor.py`, change the file to:

```python
"""Tool Executor — delegates to Tool Registry.

Kept for backward compatibility with verify.py.
"""

from app.tools.registry import ToolRegistry
from app.tools.echo_tool import echo_tool
from app.tools.cve_tool import cve_tool
from app.tools.ioc_tool import ioc_tool

# Global registry instance
tool_registry = ToolRegistry()
tool_registry.register(echo_tool)
tool_registry.register(cve_tool)
tool_registry.register(ioc_tool)
```

- [ ] **Step 2: Run all tests to verify nothing broke**

Run: `cd /data/data6T/liang/project/Agent && python -m pytest tests/ -v --tb=short`
Expected: ALL PASS (existing 57 + new IoC tests)

- [ ] **Step 3: Commit**

```bash
git add backend/app/agent/tool_executor.py
git commit -m "feat: register ioc_tool in global registry"
```

---

### Task 5: Manual Verification — End-to-End IoC Query

**Files:**
- None (manual testing)

- [ ] **Step 1: Start the server**

Run: `cd /data/data6T/liang/project/Agent/backend && nohup /data/data6T/liang/Anaconda/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 > /tmp/uvicorn.log 2>&1 &`

- [ ] **Step 2: Verify IoC tool via verify/chain endpoint**

Run:
```bash
curl -s -X POST http://localhost:8000/verify/chain \
  -H "Content-Type: application/json" \
  -d '{"message":"请使用 ioc_lookup 工具查询 IP 8.8.8.8 的威胁情报"}'
```

Expected:
- `steps.5_tools_executed` >= 1
- `tool_results[0].tool_name` == "ioc_lookup"
- `tool_results[0].success` == true
- `tool_results[0].data.ioc_value` == "8.8.8.8"
- `tool_results[0].data.risk_score` is a number
- `steps.6_final_response` contains Chinese threat analysis

- [ ] **Step 3: Verify with a suspicious IP**

Run:
```bash
curl -s -X POST http://localhost:8000/verify/chain \
  -H "Content-Type: application/json" \
  -d '{"message":"请使用 ioc_lookup 工具查询域名 evil.com 的威胁情报"}'
```

Expected: Same structure, `ioc_type` == "domain"

- [ ] **Step 4: Verify tool list includes ioc_lookup**

Run: `curl -s http://localhost:8000/verify/features | python3 -m json.tool`

Expected: `tools` list includes "ioc_lookup"
