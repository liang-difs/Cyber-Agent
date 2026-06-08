"""Web Search Tool — multi-engine search with automatic fallback.

Follows tool_protocol.md. Returns structured search results.
Engine priority: DuckDuckGo → Bing → Google (scraping).
Used when RAG and specialized tools can't answer the query.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from typing import Any

from pydantic import Field

from app.governance.tool_protocol import ToolInput, ToolResult

logger = logging.getLogger(__name__)

CACHE_TTL = 3600  # 1 hour


class WebSearchInput(ToolInput):
    """Web Search Tool input."""

    query: str = Field(..., description="搜索关键词，如漏洞名称、安全事件、攻击手法")
    max_results: int = Field(5, description="返回结果数量，默认5，最大10")


class WebSearchTool:
    """Search the web with multi-engine fallback for security intelligence."""

    name = "web_search"
    version = "v1"
    input_class = WebSearchInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "web_search",
                "description": "联网搜索互联网信息，用于查询最新漏洞情报、安全通告、攻击手法等。当知识库和专业工具无法回答时使用。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "搜索关键词",
                        },
                        "max_results": {
                            "type": "integer",
                            "description": "返回结果数量，默认5",
                        },
                    },
                    "required": ["query"],
                },
            },
        }

    async def execute(self, input_data: WebSearchInput) -> ToolResult:
        start = time.time()
        query = input_data.query.strip()
        max_results = min(max(1, input_data.max_results), 10)

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

        # Try cache first
        cached = await self._get_cached(query)
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

        # Multi-engine fallback: DuckDuckGo → Bing → Google
        engines = [
            ("DuckDuckGo", self._search_ddg),
            ("Bing", self._search_bing),
            ("Google", self._search_google),
        ]

        results = []
        engine_used = "none"

        for engine_name, engine_func in engines:
            try:
                results = await engine_func(query, max_results)
                if results:
                    engine_used = engine_name
                    logger.info("Web search via %s: %d results for '%s'", engine_name, len(results), query)
                    break
            except Exception as e:
                logger.warning("Web search via %s failed for '%s': %s", engine_name, query, e)
                continue

        if not results:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error="All search engines failed. Check network connectivity.",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        data = {
            "query": query,
            "results": results,
            "count": len(results),
            "engine": engine_used,
        }

        # Build structured evidence
        evidence_rows = []
        for r in results:
            url = r.get("url", "")
            title = r.get("title", "")
            evidence_rows.append({
                "source_type": "web",
                "source_path": url,
                "doc_id": f"web:{hashlib.md5(url.encode()).hexdigest()[:12]}",
                "key_dates": {},
                "note": title,
            })
        data["evidence"] = evidence_rows

        # Cache results
        await self._set_cached(query, data)

        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data=data,
            confidence=0.8,
            evidence_source=[f"{engine_used.lower()}://{query}"],
            trace_id=input_data.trace_id,
            execution_time_ms=int((time.time() - start) * 1000),
        )

    # ── DuckDuckGo Search ─────────────────────────────────────────

    @staticmethod
    async def _search_ddg(query: str, max_results: int) -> list[dict[str, str]]:
        """Search via DuckDuckGo (ddgs package, primary engine)."""

        def _do_search():
            from ddgs import DDGS
            with DDGS() as ddgs:
                raw = list(ddgs.text(query, max_results=max_results))
                return [
                    {
                        "title": r.get("title", ""),
                        "url": r.get("href", ""),
                        "snippet": r.get("body", ""),
                    }
                    for r in raw
                ]

        return await asyncio.get_event_loop().run_in_executor(None, _do_search)

    # ── Bing Search ───────────────────────────────────────────────

    @staticmethod
    async def _search_bing(query: str, max_results: int) -> list[dict[str, str]]:
        """Search via Bing HTML scraping (no API key)."""
        import httpx

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
        }

        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            resp = await client.get(
                "https://www.bing.com/search",
                params={"q": query, "count": str(max_results)},
                headers=headers,
            )
            resp.raise_for_status()
            html = resp.text

        results = []
        # Try multiple Bing HTML patterns
        patterns = [
            r'<li class="b_algo">\s*<h2>\s*<a href="([^"]+)"[^>]*>(.+?)</a>',
            r'<h2><a href="(https?://[^"]+)"[^>]*>(.+?)</a></h2>',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, html, re.DOTALL):
                url, title = match.group(1), match.group(2)
                title = re.sub(r"<[^>]+>", "", title).strip()
                if url.startswith("http"):
                    results.append({"title": title, "url": url, "snippet": ""})
                if len(results) >= max_results:
                    break
            if results:
                break

        return results

    # ── Google Search ─────────────────────────────────────────────

    @staticmethod
    async def _search_google(query: str, max_results: int) -> list[dict[str, str]]:
        """Search via googlesearch-python (scraping-based, no API key)."""

        def _do_search():
            from googlesearch import search
            results = []
            for url in search(query, num_results=max_results, advanced=True):
                results.append({
                    "title": getattr(url, "title", "") or "",
                    "url": getattr(url, "url", "") or str(url),
                    "snippet": getattr(url, "description", "") or "",
                })
            return results

        return await asyncio.get_event_loop().run_in_executor(None, _do_search)

    # ── Cache ─────────────────────────────────────────────────────

    @staticmethod
    def _cache_key(query: str) -> str:
        h = hashlib.md5(query.encode()).hexdigest()[:12]
        return f"web:{h}"

    async def _get_cached(self, query: str) -> dict[str, Any] | None:
        try:
            from app.core.redis import get_redis
            r = await get_redis()
            if not r:
                return None
            data = await r.get(self._cache_key(query))
            if data:
                return json.loads(data)
        except Exception:
            pass
        return None

    async def _set_cached(self, query: str, data: dict[str, Any]) -> None:
        try:
            from app.core.redis import get_redis
            r = await get_redis()
            if not r:
                return
            await r.setex(self._cache_key(query), CACHE_TTL, json.dumps(data, ensure_ascii=False))
        except Exception:
            pass


web_search_tool = WebSearchTool()
