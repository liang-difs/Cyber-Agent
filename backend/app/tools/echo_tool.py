"""
Echo Tool — 最小验证 Tool。

仅用于验证 Tool Calling 链路，非业务 Tool。
遵循 tool_protocol.md。
"""

import time
import uuid
from typing import Any

from pydantic import BaseModel, Field

from app.governance.tool_protocol import ToolInput, ToolResult


class EchoInput(ToolInput):
    """Echo Tool 输入"""

    message: str = Field(..., description="要回显的消息")


class EchoTool:
    """最小验证 Tool：回显输入消息"""

    name = "echo"
    version = "v1"

    def get_schema(self) -> dict[str, Any]:
        """返回 JSON Schema（供 LLM function calling）"""
        return {
            "type": "function",
            "function": {
                "name": "echo",
                "description": "回显用户输入的消息。用于验证 Tool Calling 链路是否正常。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "message": {
                            "type": "string",
                            "description": "要回显的消息",
                        }
                    },
                    "required": ["message"],
                },
            },
        }

    async def execute(self, input_data: EchoInput) -> ToolResult:
        """执行回显"""
        start = time.time()
        execution_time_ms = int((time.time() - start) * 1000)

        return ToolResult(
            success=True,
            tool_name=self.name,
            tool_version=self.version,
            data={"echo": input_data.message, "length": len(input_data.message)},
            error=None,
            confidence=1.0,
            evidence_source=["echo_tool_internal"],
            trace_id=input_data.trace_id,
            execution_time_ms=execution_time_ms,
        )


echo_tool = EchoTool()
