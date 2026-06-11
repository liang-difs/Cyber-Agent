"""Tool Registry — centralized tool registration and lookup.

Integrates caching and retry logic for improved reliability and performance.
"""

from __future__ import annotations

import logging
from typing import Any

from app.governance.tool_protocol import ToolResult

logger = logging.getLogger(__name__)

# Common argument aliases: LLM may send these instead of the correct field name
ARGUMENT_ALIASES: dict[str, dict[str, str]] = {
    "ioc_lookup": {"query": "value", "ip": "value", "domain": "value", "indicator": "value"},
    "ip_threat_analysis": {"query": "ip", "value": "ip", "ip_address": "ip"},
    "cve_lookup": {"query": "cve_id", "value": "cve_id", "id": "cve_id"},
    "cve_catalog": {"query": "query", "q": "query", "score": "cvss_score", "cvss": "cvss_score", "kev": "kev_only"},
    "web_search": {"query": "query", "q": "query"},
    "rag_search": {"query": "query", "q": "query"},
    "archive": {"path": "file_path", "zip_path": "file_path", "archive_path": "file_path"},
    "api_doc_parser": {"path": "file_path", "doc_path": "file_path", "swagger_url": "url", "openapi_url": "url"},
    "config_parser": {"path": "file_path", "config_path": "file_path"},
    "binary_analysis": {"path": "file_path", "bin_path": "file_path", "binary_path": "file_path"},
    "task_planner": {"description": "task_description", "task": "task_description", "plan": "task_description"},
}

# Tools that should have their results cached (read-only query tools)
CACHEABLE_TOOLS: set[str] = {
    "cve_lookup",
    "ioc_lookup",
    "ip_threat_analysis",
    "whois_lookup",
    "dns_lookup",
    "ssl_lookup",
    "hash_lookup",
}

# Tools that should have retry logic for transient failures
RETRY_TOOLS: set[str] = {
    "web_search",
    "threat_intel",
    "ioc_lookup",
    "nmap_scan",
    "vuln_scan",
}


class ToolRegistry:
    """Manages tool registration, schema access, caching, and retry."""

    def __init__(self, enable_cache: bool = True, enable_retry: bool = True):
        self._tools: dict[str, Any] = {}
        self._enable_cache = enable_cache
        self._enable_retry = enable_retry
        self._cache = None
        self._retry_configs = None

    def _get_cache(self) -> Any:
        """Lazy-load tool cache."""
        if self._cache is None and self._enable_cache:
            from app.agent.tool_cache import get_tool_cache
            self._cache = get_tool_cache()
        return self._cache

    def _get_retry_config(self, tool_name: str) -> Any:
        """Get retry config for a tool if retry is enabled."""
        if not self._enable_retry:
            return None
        if tool_name not in RETRY_TOOLS:
            return None
        from app.agent.retry import TOOL_RETRY_CONFIGS
        return TOOL_RETRY_CONFIGS.get(tool_name)

    def register(self, tool: Any) -> None:
        if tool.name in self._tools:
            raise ValueError(f"Tool '{tool.name}' already registered")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Any | None:
        return self._tools.get(name)

    def get_schemas(self) -> list[dict[str, Any]]:
        return [tool.get_schema() for tool in self._tools.values()]

    def list_names(self) -> list[str]:
        return list(self._tools.keys())

    @staticmethod
    def _normalize_arguments(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Map common LLM argument aliases to the correct field names."""
        aliases = ARGUMENT_ALIASES.get(tool_name, {})
        normalized = dict(arguments)
        for wrong_name, correct_name in aliases.items():
            if wrong_name in normalized and correct_name not in normalized:
                normalized[correct_name] = normalized.pop(wrong_name)
                logger.info("Tool '%s': mapped argument '%s' → '%s'", tool_name, wrong_name, correct_name)
        return normalized

    async def execute(self, name: str, arguments: dict[str, Any], trace_id: str, tenant_id: str = "system") -> dict[str, Any]:
        """Execute a tool with optional caching and retry.

        Flow:
        1. Check cache for cacheable tools (return immediately on hit)
        2. Validate input parameters
        3. Execute tool (with retry if configured)
        4. Cache successful results for cacheable tools
        """
        tool = self.get(name)
        if not tool:
            return ToolResult(
                success=False,
                tool_name=name,
                tool_version="unknown",
                data={},
                error=f"Tool '{name}' not found",
                confidence=0.0,
                evidence_source=[],
                trace_id=trace_id,
                execution_time_ms=0,
            ).model_dump()

        # Normalize argument names (handle LLM alias errors)
        arguments = self._normalize_arguments(name, arguments)

        # Check cache for cacheable tools
        cache = self._get_cache()
        if cache and name in CACHEABLE_TOOLS:
            cached = cache.get(name, arguments)
            if cached:
                logger.info("Tool '%s' cache hit", name)
                return cached

        # Use tool's declared input class, fallback to EchoInput
        input_cls = getattr(tool, "input_class", None)
        if input_cls is None:
            from app.tools.echo_tool import EchoInput
            input_cls = EchoInput

        try:
            input_data = input_cls(
                trace_id=trace_id,
                tenant_id=tenant_id,
                **arguments,
            )
        except Exception as e:
            logger.error("Tool '%s' input validation failed: %s", name, e)
            return ToolResult(
                success=False,
                tool_name=name,
                tool_version="v1",
                data={"raw_arguments": arguments},
                error=f"参数验证失败: {e}",
                confidence=0.0,
                evidence_source=[],
                trace_id=trace_id,
                execution_time_ms=0,
            ).model_dump()

        # Execute with retry if configured
        retry_config = self._get_retry_config(name)
        if retry_config:
            from app.agent.retry import retry_async
            try:
                result = await retry_async(tool.execute, input_data, config=retry_config)
            except Exception as e:
                logger.error("Tool '%s' execution failed after retries: %s", name, e)
                return ToolResult(
                    success=False,
                    tool_name=name,
                    tool_version="v1",
                    data={"raw_arguments": arguments},
                    error=f"Tool execution failed after retries: {e}",
                    confidence=0.0,
                    evidence_source=[],
                    trace_id=trace_id,
                    execution_time_ms=0,
                ).model_dump()
        else:
            result = await tool.execute(input_data)

        result_dict = result.model_dump()

        # Cache successful results for cacheable tools
        if cache and name in CACHEABLE_TOOLS and result_dict.get("success"):
            cache.set(name, arguments, result_dict)

        return result_dict
