"""CVE Lookup Tool — queries NVD API 2.0 for vulnerability details.

Follows tool_protocol.md. Returns structured CVE data.
No LLM interpretation — Agent layer handles that.
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional

import httpx
from pydantic import Field

from app.core.config import get_settings
from app.governance.tool_protocol import ToolInput, ToolResult


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL = 86400  # 24 hours


class CVEInput(ToolInput):
    """CVE Tool input."""

    cve_id: str = Field(..., description="CVE 编号，如 CVE-2024-3400")


class CVELookupTool:
    """查询 NVD API 获取 CVE 详情。"""

    name = "cve_lookup"
    version = "v1"
    input_class = CVEInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "cve_lookup",
                "description": "查询 CVE 漏洞详情，返回 CVSS 评分、描述、受影响产品和参考链接。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "cve_id": {
                            "type": "string",
                            "description": "CVE 编号，格式如 CVE-2024-3400",
                        }
                    },
                    "required": ["cve_id"],
                },
            },
        }

    async def execute(self, input_data: CVEInput) -> ToolResult:
        start = time.time()
        cve_id = input_data.cve_id.strip().upper()

        # Try cache first
        cached = await self._get_cached(cve_id)
        if cached:
            cached_e = dict(cached)
            if "evidence" not in cached_e:
                cached_e["evidence"] = [
                    {
                        "source_type": "cache",
                        "source_path": f"redis://cve:{cve_id}",
                        "doc_id": f"cve-cache:{cve_id}",
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
                evidence_source=["cache", f"redis://cve:{cve_id}"],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        # Query NVD API
        try:
            data = await self._query_nvd(cve_id)
        except httpx.HTTPStatusError as e:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error=f"NVD API error: {e.response.status_code}",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )
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

        # Parse NVD response
        result_data = self._parse_nvd_response(cve_id, data)

        # Build structured evidence
        evidence_rows = []
        if result_data.get("found"):
            evidence_rows.append(
                {
                    "source_type": "cve",
                    "source_path": "nvd.nist.gov",
                    "doc_id": cve_id,
                    "key_dates": {
                        "published": result_data.get("published", ""),
                        "last_modified": result_data.get("last_modified", ""),
                    },
                    "note": "NVD metadata",
                }
            )

        result_data["evidence"] = evidence_rows

        # Cache result
        await self._set_cached(cve_id, result_data)

        evidence_srcs = [r.get("source_path", "") for r in evidence_rows]
        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data=result_data,
            confidence=1.0 if result_data.get("found") else 0.0,
            evidence_source=evidence_srcs if evidence_srcs else [],
            trace_id=input_data.trace_id,
            execution_time_ms=int((time.time() - start) * 1000),
        )

    async def _query_nvd(self, cve_id: str) -> dict:
        """Query NVD API 2.0."""
        import logging
        logger = logging.getLogger(__name__)

        settings = get_settings()
        headers = {}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                NVD_API_URL,
                params={"cveId": cve_id},
                headers=headers,
            )

            # NVD returns 404 with "Invalid apiKey" message for bad keys
            if resp.status_code == 404 and settings.nvd_api_key:
                msg = resp.headers.get("message", "")
                if "Invalid apiKey" in msg:
                    logger.warning("NVD API key invalid, retrying without key")
                    resp = await client.get(
                        NVD_API_URL,
                        params={"cveId": cve_id},
                    )

            resp.raise_for_status()
            return resp.json()

    def _parse_nvd_response(self, cve_id: str, data: dict) -> dict[str, Any]:
        """Parse NVD API response into structured data."""
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {"cve_id": cve_id, "found": False}

        cve = vulns[0].get("cve", {})

        # Description
        descriptions = cve.get("descriptions", [])
        desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        # CVSS
        cvss_score = 0.0
        severity = "UNKNOWN"
        metrics = cve.get("metrics", {})
        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version_key in metrics and metrics[version_key]:
                cvss_data = metrics[version_key][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                break

        # Affected products
        products = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        products.append(match.get("criteria", ""))

        # References
        refs = [r.get("url", "") for r in cve.get("references", [])]

        return {
            "cve_id": cve_id,
            "found": True,
            "description": desc_en,
            "cvss_score": cvss_score,
            "severity": severity,
            "affected_products": products[:10],
            "references": refs[:5],
            "published": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
        }

    async def _get_cached(self, cve_id: str) -> Optional[dict]:
        """Get from Redis cache."""
        redis = await _get_redis()
        if not redis:
            return None
        try:
            data = await redis.get(f"cve:{cve_id}")
            if data:
                return json.loads(data)
        except Exception:
            pass
        return None

    async def _set_cached(self, cve_id: str, data: dict) -> None:
        """Set Redis cache."""
        redis = await _get_redis()
        if not redis:
            return
        try:
            await redis.set(f"cve:{cve_id}", json.dumps(data, ensure_ascii=False), ex=CACHE_TTL)
        except Exception:
            pass


from app.core.redis import get_redis as _get_redis


cve_tool = CVELookupTool()
