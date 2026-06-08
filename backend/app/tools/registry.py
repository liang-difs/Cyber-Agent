"""Tool Registry — centralized tool registration and lookup."""

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


class ToolRegistry:
    """Manages tool registration and schema access."""

    def __init__(self):
        self._tools: dict[str, Any] = {}

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

        result = await tool.execute(input_data)
        return result.model_dump()
