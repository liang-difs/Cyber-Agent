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

IP_API_URL = "https://ip-api.com/json"
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
            # Ensure cached results include structured evidence entries
            cached_e = dict(cached)
            if "evidence" not in cached_e:
                cached_e["evidence"] = [
                    {
                        "source_type": "cache",
                        "source_path": f"redis://ip:{_sha256(ip)}",
                        "doc_id": f"ip-cache:{_sha256(ip)}",
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

        # Build structured evidence entries for traceability
        evidence_rows = []
        if geo_data:
            evidence_rows.append(
                {
                    "source_type": "ip",
                    "source_path": "ip-api.com",
                    "doc_id": f"ip-api:{ip}",
                    "key_dates": {},
                    "note": "geoip lookup",
                }
            )
        if abuse_data:
            evidence_rows.append(
                {
                    "source_type": "abuse",
                    "source_path": "abuseipdb.com",
                    "doc_id": f"abuseipdb:{ip}",
                    "key_dates": {"last_reported_at": abuse_data.get("last_reported_at", "")},
                    "note": "abuseipdb report",
                }
            )

        # Attach structured evidence to the returned data
        result_data["evidence"] = evidence_rows

        # Cache result
        await self._set_cached(ip, result_data)

        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data=result_data,
            confidence=1.0,
            evidence_source=[row.get("source_path", "") for row in evidence_rows],
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
        redis = await _get_redis()
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
        redis = await _get_redis()
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


from app.core.redis import get_redis as _get_redis


ip_tool = IPThreatTool()
