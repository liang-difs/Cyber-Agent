"""Structured CVE catalog tool for list and aggregation queries."""

from __future__ import annotations

import time
from typing import Any, Optional

from pydantic import Field

from app.governance.tool_protocol import ToolInput, ToolResult
from app.rag.cve_catalog import query_cve_catalog


class CVECatalogInput(ToolInput):
    """Structured CVE query input."""

    query: Optional[str] = Field(default=None, description="自然语言筛选条件，如 2024 CVSS 10.0 KEV")
    year: Optional[int] = Field(default=None, description="披露年份，如 2024")
    cvss_score: Optional[float] = Field(default=None, description="CVSS 评分，如 10.0")
    kev_only: bool = Field(default=False, description="仅返回已列入 KEV 的 CVE")
    severity: Optional[str] = Field(default=None, description="严重等级，如 CRITICAL")
    keyword: Optional[str] = Field(default=None, description="关键字过滤")
    limit: int = Field(default=20, ge=1, le=100, description="返回结果数量")


class CVECatalogTool:
    """Query the public CVE + KEV catalog with structured filters."""

    name = "cve_catalog"
    version = "v1"
    input_class = CVECatalogInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "cve_catalog",
                "description": "按年份、CVSS、KEV、严重等级或关键字筛选并列出 CVE / KEV 记录。适用于批量列表、统计和交集查询。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "自然语言筛选条件"},
                        "year": {"type": "integer", "description": "披露年份"},
                        "cvss_score": {"type": "number", "description": "CVSS 评分"},
                        "kev_only": {"type": "boolean", "description": "仅返回 KEV"},
                        "severity": {"type": "string", "description": "严重等级"},
                        "keyword": {"type": "string", "description": "关键字过滤"},
                        "limit": {"type": "integer", "description": "返回条数，默认 20，最大 100"},
                    },
                    "required": [],
                },
            },
        }

    async def execute(self, input_data: CVECatalogInput) -> ToolResult:
        start = time.time()

        try:
            data = query_cve_catalog(
                query=input_data.query,
                year=input_data.year,
                cvss_score=input_data.cvss_score,
                kev_only=input_data.kev_only,
                severity=input_data.severity,
                keyword=input_data.keyword,
                limit=input_data.limit,
            )
        except Exception as exc:
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                data={},
                error=f"Query failed: {exc}",
                confidence=0.0,
                evidence_source=[],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data=data,
            confidence=0.95 if data.get("matched_count", 0) else 0.0,
            evidence_source=["kb_public_all_v1", "source_type:cve", "source_type:kev"],
            trace_id=input_data.trace_id,
            execution_time_ms=int((time.time() - start) * 1000),
        )


cve_catalog_tool = CVECatalogTool()