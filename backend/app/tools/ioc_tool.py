"""IoC Lookup Tool — queries OTX AlienVault and VirusTotal for threat intelligence.

Follows tool_protocol.md. Returns structured IoC data.
No LLM interpretation — Agent layer handles that.
"""

from __future__ import annotations

import asyncio
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


def _sha256(value: str) -> str:
    """Return SHA256 hex digest of value."""
    return hashlib.sha256(value.encode()).hexdigest()


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
                "description": "查询 IoC（IP/域名/Hash/URL）的威胁情报，返回风险评分、标签和多源数据。支持批量：value 用逗号分隔多个 IoC 一次查询。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "value": {
                            "type": "string",
                            "description": "IoC 值，如 1.2.3.4、evil.com、文件哈希。支持逗号分隔批量：1.2.3.4,evil.com,hash",
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
        raw_value = input_data.value.strip()

        # 批量模式：检测逗号/换行分隔的多个 IoC
        separators = [",", "\n", ";"]
        values = [raw_value]
        for sep in separators:
            if sep in raw_value:
                values = [v.strip() for v in raw_value.split(sep) if v.strip()]
                break

        if len(values) > 1:
            return await self._batch_execute(values, input_data, start)

        # 单个查询
        return await self._single_execute(raw_value, input_data.type, input_data, start)

    async def _batch_execute(
        self, values: list[str], input_data: IoCInput, start: float
    ) -> ToolResult:
        """并发批量查询多个 IoC。"""
        tasks = [
            self._single_execute(v, "auto", input_data, start)
            for v in values[:10]  # 最多 10 个
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        items = []
        for v, r in zip(values[:10], results):
            if isinstance(r, Exception):
                items.append({"ioc_value": v, "error": str(r), "found": False})
            elif isinstance(r, ToolResult) and r.success:
                items.append(r.data)
            else:
                items.append({"ioc_value": v, "error": "query failed", "found": False})

        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data={
                "batch": True,
                "count": len(items),
                "items": items,
            },
            confidence=0.8,
            evidence_source=[f"ioc_batch:{len(items)}"],
            trace_id=input_data.trace_id,
            execution_time_ms=int((time.time() - start) * 1000),
        )

    async def _single_execute(
        self, value: str, ioc_type: str, input_data: IoCInput, start: float
    ) -> ToolResult:
        """单个 IoC 查询。"""
        ioc_type = detect_ioc_type(value, ioc_type)
        value = value.strip()

        # Try cache first
        cached = await self._get_cached(ioc_type, value)
        if cached:
            cached_e = dict(cached)
            if "evidence" not in cached_e:
                cached_e["evidence"] = [
                    {
                        "source_type": "cache",
                        "source_path": f"redis://ioc:{ioc_type}:{_sha256(value)}",
                        "doc_id": f"ioc-cache:{ioc_type}:{_sha256(value)}",
                        "key_dates": {},
                        "note": "cached result",
                    }
                ]
            return ToolResult(
                success=True,
                tool_name=self.name,
                tool_version=self.version,
                data=cached_e,
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

        # Build structured evidence entries
        evidence_rows = []
        for s in sources:
            if s.get("source") == "otx":
                evidence_rows.append(
                    {
                        "source_type": "otx",
                        "source_path": "otx.alienvault.com",
                        "doc_id": f"otx:{ioc_type}:{value}",
                        "key_dates": {},
                        "note": "otx pulses",
                    }
                )
            elif s.get("source") == "virustotal":
                evidence_rows.append(
                    {
                        "source_type": "virustotal",
                        "source_path": "virustotal.com",
                        "doc_id": f"virustotal:{ioc_type}:{value}",
                        "key_dates": {},
                        "note": "virustotal analysis",
                    }
                )

        result_data["evidence"] = evidence_rows

        # Cache result
        await self._set_cached(ioc_type, value, result_data)

        evidence_srcs = [r.get("source_path", "") for r in evidence_rows]
        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data=result_data,
            confidence=1.0 if sources else 0.0,
            evidence_source=evidence_srcs if evidence_srcs else [],
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
        redis = await _get_redis()
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
        redis = await _get_redis()
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


from app.core.redis import get_redis as _get_redis


ioc_tool = IoCLookupTool()
