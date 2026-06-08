"""Hash Lookup Tool — queries threat intelligence platforms for file hash reputation.

Supports VirusTotal and MalwareBazaar. Detects hash type automatically.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

import httpx
from pydantic import Field

from app.core.config import get_settings
from app.governance.tool_protocol import ToolInput, ToolResult

logger = logging.getLogger(__name__)

_VT_API = "https://www.virustotal.com/api/v3"
_MB_API = "https://mb-api.abuse.ch/api/v1"
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")


def _detect_hash_type(h: str) -> str:
    h = h.strip().lower()
    if len(h) == 64:
        return "sha256"
    if len(h) == 40:
        return "sha1"
    if len(h) == 32:
        return "md5"
    return "unknown"


class HashLookupInput(ToolInput):
    hash_value: str = Field(..., description="文件哈希值（MD5/SHA1/SHA256）")
    sources: str = Field(default="vt,mb", description="查询来源：vt(VirusTotal), mb(MalwareBazaar)")


async def _query_virustotal(hash_value: str) -> dict[str, Any]:
    settings = get_settings()
    api_key = getattr(settings, "vt_api_key", "") or ""
    if not api_key:
        return {"source": "virustotal", "error": "VT_API_KEY not configured"}
    headers = {"x-apikey": api_key}
    url = f"{_VT_API}/files/{hash_value}"
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 404:
                return {"source": "virustotal", "found": False}
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "source": "virustotal",
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "total_engines": sum(stats.values()),
                "file_type": data.get("type_description", ""),
                "file_size": data.get("size", 0),
                "names": data.get("names", [])[:5],
                "tags": data.get("tags", [])[:10],
                "reputation": data.get("reputation", 0),
                "popular_threat_name": (
                    data.get("popular_threat_classification", {})
                    .get("suggested_threat_label", "")
                ),
            }
    except Exception as e:
        return {"source": "virustotal", "error": str(e)}


async def _query_malwarebazaar(hash_value: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(_MB_API, data={"query": "get_info", "hash": hash_value})
            resp.raise_for_status()
            body = resp.json()
            if body.get("query_status") == "hash_not_found":
                return {"source": "malwarebazaar", "found": False}
            items = body.get("data", [])
            if not items:
                return {"source": "malwarebazaar", "found": False}
            item = items[0]
            return {
                "source": "malwarebazaar",
                "found": True,
                "file_type": item.get("file_type", ""),
                "file_size": item.get("file_size", 0),
                "signature": item.get("signature", ""),
                "tags": item.get("tags", [])[:10],
                "first_seen": item.get("first_seen", ""),
                "reporter": item.get("reporter", ""),
                "delivery_method": item.get("delivery_method", ""),
            }
    except Exception as e:
        return {"source": "malwarebazaar", "error": str(e)}


class HashLookupTool:
    name = "hash_lookup"
    version = "v1"
    input_class = HashLookupInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": (
                    "查询文件哈希（MD5/SHA1/SHA256）的威胁情报。"
                    "支持 VirusTotal 和 MalwareBazaar。自动检测哈希类型。"
                    "返回恶意软件家族、检测率、文件类型等信息。"
                    "应急响应和 CTF 取证场景使用。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "hash_value": {"type": "string", "description": "文件哈希值"},
                        "sources": {"type": "string", "description": "查询来源"},
                    },
                    "required": ["hash_value"],
                },
            },
        }

    async def execute(self, input_data: HashLookupInput) -> ToolResult:
        start = time.monotonic()
        hash_val = input_data.hash_value.strip().lower()
        if not _HASH_RE.match(hash_val):
            return ToolResult(
                success=False, tool_name=self.name, tool_version=self.version,
                data={}, error=f"Invalid hash: expected MD5/SHA1/SHA256, got '{hash_val[:20]}'",
                confidence=0.0, evidence_source=[], trace_id=input_data.trace_id,
                execution_time_ms=int((time.monotonic() - start) * 1000),
            )
        hash_type = _detect_hash_type(hash_val)
        sources = [s.strip().lower() for s in input_data.sources.split(",")]
        results: list[dict[str, Any]] = []
        if "vt" in sources:
            results.append(await _query_virustotal(hash_val))
        if "mb" in sources:
            results.append(await _query_malwarebazaar(hash_val))
        malicious_count = 0
        total_engines = 0
        for r in results:
            if r.get("source") == "virustotal" and r.get("found"):
                malicious_count += r.get("malicious", 0)
                total_engines += r.get("total_engines", 0)
        if total_engines > 0:
            rate = malicious_count / total_engines
            if rate > 0.3:
                verdict = "malicious"
            elif rate > 0.1:
                verdict = "suspicious"
            elif malicious_count > 0:
                verdict = "low_risk"
            else:
                verdict = "clean"
        elif any(r.get("found") for r in results):
            verdict = "found"
        else:
            verdict = "unknown"
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return ToolResult(
            success=True, tool_name=self.name, tool_version=self.version,
            data={
                "hash": hash_val, "hash_type": hash_type, "verdict": verdict,
                "detection_rate": f"{malicious_count}/{total_engines}" if total_engines else "N/A",
                "results": results,
            },
            error=None, confidence=0.9 if verdict != "unknown" else 0.3,
            evidence_source=[r.get("source", "") for r in results if r.get("found")],
            trace_id=input_data.trace_id, execution_time_ms=elapsed_ms,
        )
