"""Threat Intelligence Tool — queries external threat intel APIs.

查询外部威胁情报源（Shodan、GreyNoise、AbuseIPDB）。
Follows tool_protocol.md. Returns structured threat data.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from typing import Any, Optional

import httpx
from pydantic import Field

from app.core.config import get_settings
from app.governance.tool_protocol import ToolInput, ToolResult

logger = logging.getLogger(__name__)

CACHE_TTL = 7200  # 2 hours


class ThreatIntelInput(ToolInput):
    """Threat Intelligence Tool input."""

    query: str = Field(..., description="查询目标：IP 地址、域名或哈希")
    sources: str = Field(
        default="auto",
        description="情报源：auto(自动选择), shodan, greynoise, abuseipdb, all(全部)",
    )


class ThreatIntelTool:
    """Query external threat intelligence sources."""

    name = "threat_intel"
    version = "v1"
    input_class = ThreatIntelInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "threat_intel",
                "description": (
                    "查询外部威胁情报（Shodan/GreyNoise/AbuseIPDB），获取 IP 信誉、"
                    "开放端口、已知恶意活动、扫描行为等信息。用于补充 IoC 查询的深度。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "IP 地址、域名或哈希",
                        },
                        "sources": {
                            "type": "string",
                            "description": "情报源：auto, shodan, greynoise, abuseipdb, all",
                            "enum": ["auto", "shodan", "greynoise", "abuseipdb", "all"],
                        },
                    },
                    "required": ["query"],
                },
            },
        }

    async def execute(self, input_data: ThreatIntelInput) -> ToolResult:
        start = time.time()
        query = input_data.query.strip()
        sources = input_data.sources

        if not query:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error="Empty query",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Check cache
        cached = await self._get_cached(query, sources)
        if cached:
            return ToolResult(
                success=True,
                tool_name=self.name,
                tool_version=self.version,
                data=cached,
                confidence=0.8,
                evidence_source=["cache"],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        settings = get_settings()
        results = {}
        evidence_sources = []

        # Determine which sources to query
        source_list = self._resolve_sources(sources, settings)

        # Query sources concurrently
        tasks = []
        for source_name, source_func in source_list:
            tasks.append(self._query_source(source_name, source_func, query))

        if not tasks:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error="No API keys configured. Set SHODAN_API_KEY, GREYNOISE_API_KEY, or AbuseIPDB_API_KEY.",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        for source_name, result in source_list:
            idx = list(zip(*source_list))[0].index(source_name) if source_list else -1
            if idx < len(raw_results) and not isinstance(raw_results[idx], Exception):
                source_result = raw_results[idx]
                if source_result:
                    results[source_name] = source_result
                    evidence_sources.append(f"{source_name}://{query}")

        if not results:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error="All threat intel sources failed or returned no data",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Aggregate results
        aggregated = self._aggregate_results(query, results)

        # Cache
        await self._set_cached(query, sources, aggregated)

        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data=aggregated,
            confidence=0.85,
            evidence_source=evidence_sources,
            trace_id=input_data.trace_id,
            execution_time_ms=int((time.time() - start) * 1000),
        )

    def _resolve_sources(self, sources: str, settings) -> list[tuple[str, Any]]:
        """Resolve which sources to query based on config and request."""
        available = []

        if settings.shodan_api_key:
            available.append(("shodan", self._query_shodan))
        if settings.greynoise_api_key:
            available.append(("greynoise", self._query_greynoise))
        if settings.abuseipdb_api_key:
            available.append(("abuseipdb", self._query_abuseipdb))

        if sources == "all":
            return available
        if sources == "auto":
            return available[:2]  # Use up to 2 sources in auto mode

        # Specific source requested
        source_map = {
            "shodan": ("shodan", self._query_shodan),
            "greynoise": ("greynoise", self._query_greynoise),
            "abuseipdb": ("abuseipdb", self._query_abuseipdb),
        }
        if sources in source_map:
            name, func = source_map[sources]
            # Only return if API key is configured
            key_attr = f"{name}_api_key"
            if hasattr(settings, key_attr) and getattr(settings, key_attr):
                return [(name, func)]

        return available

    async def _query_source(self, name: str, func, query: str) -> Optional[dict]:
        """Query a single source with error handling."""
        try:
            return await func(query)
        except Exception as e:
            logger.warning("Threat intel source %s failed for '%s': %s", name, query, e)
            return None

    # ── Shodan ────────────────────────────────────────────────────

    async def _query_shodan(self, query: str) -> Optional[dict[str, Any]]:
        """Query Shodan API for host information."""
        settings = get_settings()
        api_key = settings.shodan_api_key
        if not api_key:
            return None

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/{query}",
                params={"key": api_key},
            )
            if resp.status_code == 404:
                return {"found": False, "source": "shodan"}
            resp.raise_for_status()
            data = resp.json()

        return {
            "found": True,
            "source": "shodan",
            "ip": data.get("ip_str", query),
            "org": data.get("org", ""),
            "os": data.get("os"),
            "ports": data.get("ports", []),
            "vulns": data.get("vulns", []),
            "hostnames": data.get("hostnames", []),
            "country_code": data.get("country_code", ""),
            "city": data.get("city", ""),
            "last_update": data.get("last_update", ""),
            "tags": data.get("tags", []),
            "cpes": data.get("cpes", []),
        }

    # ── GreyNoise ─────────────────────────────────────────────────

    async def _query_greynoise(self, query: str) -> Optional[dict[str, Any]]:
        """Query GreyNoise API for IP context."""
        settings = get_settings()
        api_key = settings.greynoise_api_key
        if not api_key:
            return None

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"https://api.greynoise.io/v3/community/{query}",
                headers={"key": api_key},
            )
            if resp.status_code == 404:
                return {"found": False, "source": "greynoise"}
            resp.raise_for_status()
            data = resp.json()

        return {
            "found": True,
            "source": "greynoise",
            "ip": data.get("ip", query),
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "classification": data.get("classification", "unknown"),
            "name": data.get("name", ""),
            "link": data.get("link", ""),
            "last_seen": data.get("last_seen", ""),
            "message": data.get("message", ""),
        }

    # ── AbuseIPDB ─────────────────────────────────────────────────

    async def _query_abuseipdb(self, query: str) -> Optional[dict[str, Any]]:
        """Query AbuseIPDB for IP reputation."""
        settings = get_settings()
        api_key = settings.abuseipdb_api_key
        if not api_key:
            return None

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": query, "maxAgeInDays": 90, "verbose": ""},
                headers={"Key": api_key, "Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})

        return {
            "found": True,
            "source": "abuseipdb",
            "ip": data.get("ipAddress", query),
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "is_public": data.get("isPublic", False),
            "is_whitelisted": data.get("isWhitelisted", False),
            "usage_type": data.get("usageType", ""),
            "isp": data.get("isp", ""),
            "domain": data.get("domain", ""),
            "country_code": data.get("countryCode", ""),
            "last_reported_at": data.get("lastReportedAt", ""),
        }

    # ── Aggregation ───────────────────────────────────────────────

    def _aggregate_results(self, query: str, results: dict[str, dict]) -> dict[str, Any]:
        """Aggregate results from multiple sources."""
        aggregated = {
            "query": query,
            "sources_queried": list(results.keys()),
            "sources": results,
            "risk_score": 0,
            "risk_level": "unknown",
            "summary": "",
        }

        # Calculate weighted risk score
        scores = []
        if "abuseipdb" in results and results["abuseipdb"].get("found"):
            abuse_score = results["abuseipdb"].get("abuse_confidence_score", 0)
            scores.append(("abuseipdb", abuse_score, 0.4))

        if "greynoise" in results and results["greynoise"].get("found"):
            gn = results["greynoise"]
            gn_score = 80 if gn.get("classification") == "malicious" else 40 if gn.get("noise") else 10
            scores.append(("greynoise", gn_score, 0.3))

        if "shodan" in results and results["shodan"].get("found"):
            vulns = len(results["shodan"].get("vulns", []))
            shodan_score = min(vulns * 15, 100)
            scores.append(("shodan", shodan_score, 0.3))

        if scores:
            total_weight = sum(w for _, _, w in scores)
            weighted_score = sum(s * w for _, s, w in scores) / total_weight if total_weight > 0 else 0
            aggregated["risk_score"] = round(weighted_score)

        # Risk level
        score = aggregated["risk_score"]
        if score >= 80:
            aggregated["risk_level"] = "critical"
        elif score >= 60:
            aggregated["risk_level"] = "high"
        elif score >= 40:
            aggregated["risk_level"] = "medium"
        elif score >= 20:
            aggregated["risk_level"] = "low"
        else:
            aggregated["risk_level"] = "safe"

        # Summary
        parts = []
        for source, data in results.items():
            if not data.get("found"):
                continue
            if source == "shodan":
                parts.append(f"Shodan: {len(data.get('ports', []))} ports, {len(data.get('vulns', []))} vulns")
            elif source == "greynoise":
                cls = data.get("classification", "unknown")
                parts.append(f"GreyNoise: {cls}")
            elif source == "abuseipdb":
                score = data.get("abuse_confidence_score", 0)
                parts.append(f"AbuseIPDB: {score}% confidence")

        aggregated["summary"] = " | ".join(parts) if parts else "No threat intelligence found"

        return aggregated

    # ── Cache ─────────────────────────────────────────────────────

    @staticmethod
    def _cache_key(query: str, sources: str) -> str:
        h = hashlib.md5(f"{query}:{sources}".encode()).hexdigest()[:12]
        return f"threat_intel:{h}"

    async def _get_cached(self, query: str, sources: str) -> Optional[dict]:
        try:
            from app.core.redis import get_redis
            r = await get_redis()
            if not r:
                return None
            data = await r.get(self._cache_key(query, sources))
            if data:
                return json.loads(data)
        except Exception:
            pass
        return None

    async def _set_cached(self, query: str, sources: str, data: dict) -> None:
        try:
            from app.core.redis import get_redis
            r = await get_redis()
            if not r:
                return
            await r.setex(self._cache_key(query, sources), CACHE_TTL, json.dumps(data, ensure_ascii=False))
        except Exception:
            pass


threat_intel_tool = ThreatIntelTool()
