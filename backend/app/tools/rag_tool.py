"""RAG Search Tool — retrieves relevant knowledge for the Agent.

Follows tool_protocol.md. Returns retrieved context.
No LLM interpretation — Agent layer handles that.
"""

from __future__ import annotations

import time
from typing import Any

from pydantic import Field

from app.governance.tool_protocol import ToolInput, ToolResult
from app.rag.pipeline import RAGPipeline


class RAGInput(ToolInput):
    query: str = Field(..., description="检索查询，如 CVE 编号、漏洞描述、攻击类型")


class RAGTool:
    name = "rag_search"
    version = "v1"
    input_class = RAGInput

    def __init__(self):
        self._pipeline: RAGPipeline | None = None

    def _get_pipeline(self) -> RAGPipeline:
        if self._pipeline is None:
            self._pipeline = RAGPipeline()
        return self._pipeline

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "rag_search",
                "description": "从安全知识库中检索相关信息，用于补充 CVE、ATT&CK 等背景知识。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "检索查询，如 CVE 编号、漏洞描述、攻击类型",
                        }
                    },
                    "required": ["query"],
                },
            },
        }

    async def execute(self, input_data: RAGInput) -> ToolResult:
        start = time.time()
        pipeline = self._get_pipeline()
        results = pipeline.retrieve(input_data.query, top_k=4)

        if not results:
            return ToolResult(
                success=True,
                tool_name=self.name,
                tool_version=self.version,
                data={"query": input_data.query, "results": [], "found": False},
                confidence=0.0,
                evidence_source=["rag_pipeline"],
                trace_id=input_data.trace_id,
                execution_time_ms=int((time.time() - start) * 1000),
            )

        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data={"query": input_data.query, "results": results, "found": True},
            confidence=0.8,
            evidence_source=["rag_pipeline"],
            trace_id=input_data.trace_id,
            execution_time_ms=int((time.time() - start) * 1000),
        )


rag_tool = RAGTool()
