"""Response Action Tool — Execute automated response actions.

响应动作工具：执行自动响应动作。
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.governance.tool_protocol import ToolInput, ToolResult
from app.response.action_manager import get_action_manager

logger = logging.getLogger(__name__)


class ResponseActionInput(ToolInput):
    """响应动作工具输入"""

    action_type: str = Field(
        ...,
        description="动作类型: block_ip, isolate_host, notify, quarantine_file, disable_account, auto_respond"
    )
    params: dict[str, Any] = Field(default_factory=dict, description="动作参数")
    threat_data: Optional[dict[str, Any]] = Field(default=None, description="威胁数据(用于auto_respond)")


class ResponseActionTool:
    """响应动作工具"""

    name = "response_action"
    version = "v1"
    input_class = ResponseActionInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "response_action",
                "description": (
                    "执行自动响应动作。支持以下动作类型：\n"
                    "- block_ip: 阻断指定IP地址\n"
                    "- isolate_host: 隔离受感染主机\n"
                    "- notify: 发送安全事件通知\n"
                    "- quarantine_file: 隔离恶意文件\n"
                    "- disable_account: 禁用被入侵账户\n"
                    "- auto_respond: 根据威胁数据自动选择响应动作\n\n"
                    "可用于应急响应、威胁处置、安全自动化。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action_type": {
                            "type": "string",
                            "enum": ["block_ip", "isolate_host", "notify", "quarantine_file", "disable_account", "auto_respond"],
                            "description": "动作类型",
                        },
                        "params": {
                            "type": "object",
                            "description": "动作参数",
                            "properties": {
                                "ip": {"type": "string", "description": "IP地址(用于block_ip)"},
                                "host": {"type": "string", "description": "主机标识(用于isolate_host)"},
                                "file_path": {"type": "string", "description": "文件路径(用于quarantine_file)"},
                                "username": {"type": "string", "description": "用户名(用于disable_account)"},
                                "recipients": {"type": "array", "items": {"type": "string"}, "description": "通知接收者"},
                                "message": {"type": "string", "description": "通知消息"},
                                "reason": {"type": "string", "description": "动作原因"},
                                "duration_seconds": {"type": "integer", "description": "阻断时长(秒)"},
                            },
                        },
                        "threat_data": {
                            "type": "object",
                            "description": "威胁数据(用于auto_respond)",
                            "properties": {
                                "type": {"type": "string", "description": "威胁类型"},
                                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                                "ip": {"type": "string"},
                                "host": {"type": "string"},
                            },
                        },
                    },
                    "required": ["action_type"],
                },
            },
        }

    async def execute(self, input_data: ResponseActionInput) -> ToolResult:
        """执行响应动作"""
        start_time = time.time()
        trace_id = input_data.trace_id

        try:
            action_manager = get_action_manager()
            action_type = input_data.action_type

            if action_type == "auto_respond":
                # 自动响应模式
                if not input_data.threat_data:
                    return ToolResult(
                        success=False,
                        tool_name=self.name,
                        tool_version=self.version,
                        error="threat_data is required for auto_respond",
                        trace_id=trace_id,
                    )

                results = await action_manager.auto_respond(input_data.threat_data)

                # 汇总结果
                successful = sum(1 for r in results if r.success)
                failed = len(results) - successful

                return ToolResult(
                    success=failed == 0,
                    tool_name=self.name,
                    tool_version=self.version,
                    data={
                        "action_type": "auto_respond",
                        "total_actions": len(results),
                        "successful": successful,
                        "failed": failed,
                        "results": [
                            {
                                "action_type": r.action_type,
                                "status": r.status.value,
                                "success": r.success,
                                "message": r.message,
                            }
                            for r in results
                        ],
                    },
                    confidence=0.9 if failed == 0 else 0.5,
                    evidence_source=["response_action"],
                    trace_id=trace_id,
                    execution_time_ms=int((time.time() - start_time) * 1000),
                )

            else:
                # 单个动作执行
                result = await action_manager.execute_action(action_type, input_data.params)

                return ToolResult(
                    success=result.success,
                    tool_name=self.name,
                    tool_version=self.version,
                    data={
                        "action_id": result.action_id,
                        "action_type": result.action_type,
                        "status": result.status.value,
                        "message": result.message,
                        "details": result.details,
                        "rollback_available": result.rollback_available,
                    },
                    confidence=0.9 if result.success else 0.3,
                    evidence_source=["response_action"],
                    trace_id=trace_id,
                    execution_time_ms=int((time.time() - start_time) * 1000),
                )

        except Exception as e:
            logger.error("Response action failed: %s", e)
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                error=str(e),
                trace_id=trace_id,
                execution_time_ms=int((time.time() - start_time) * 1000),
            )


# 创建工具实例
response_action_tool = ResponseActionTool()
