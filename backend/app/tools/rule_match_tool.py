"""Rule Matching Tool — Match logs/files against Sigma/YARA rules.

规则匹配工具：使用Sigma/YARA规则匹配日志和文件。
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.governance.tool_protocol import ToolInput, ToolResult
from app.rules.rule_manager import get_rule_manager

logger = logging.getLogger(__name__)


class RuleMatchInput(ToolInput):
    """规则匹配工具输入"""

    match_type: str = Field(
        ...,
        description="匹配类型: log(日志匹配), file(文件匹配), data(数据匹配)"
    )
    content: Optional[str] = Field(default=None, description="日志内容或数据(base64编码)")
    file_path: Optional[str] = Field(default=None, description="文件路径")
    logsource: Optional[dict[str, str]] = Field(default=None, description="日志源信息")
    rule_type: Optional[str] = Field(default=None, description="规则类型: sigma, yara, all")


class RuleMatchTool:
    """规则匹配工具"""

    name = "rule_match"
    version = "v1"
    input_class = RuleMatchInput

    def get_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "rule_match",
                "description": (
                    "使用Sigma/YARA规则匹配日志和文件。"
                    "支持三种匹配模式：\n"
                    "- log: 匹配日志事件（使用Sigma规则）\n"
                    "- file: 匹配文件（使用YARA规则）\n"
                    "- data: 匹配数据（使用YARA规则）\n\n"
                    "返回匹配的规则、严重等级、置信度和处置建议。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "match_type": {
                            "type": "string",
                            "enum": ["log", "file", "data"],
                            "description": "匹配类型",
                        },
                        "content": {
                            "type": "string",
                            "description": "日志内容或数据(base64编码)",
                        },
                        "file_path": {
                            "type": "string",
                            "description": "文件路径",
                        },
                        "logsource": {
                            "type": "object",
                            "description": "日志源信息，如 category, product, service",
                        },
                        "rule_type": {
                            "type": "string",
                            "enum": ["sigma", "yara", "all"],
                            "description": "规则类型，默认all",
                        },
                    },
                    "required": ["match_type"],
                },
            },
        }

    async def execute(self, input_data: RuleMatchInput) -> ToolResult:
        """执行规则匹配"""
        start_time = time.time()
        trace_id = input_data.trace_id
        tenant_id = input_data.tenant_id

        try:
            rule_manager = get_rule_manager()
            matches = []

            if input_data.match_type == "log":
                # 日志匹配
                if not input_data.content:
                    return ToolResult(
                        success=False,
                        tool_name=self.name,
                        tool_version=self.version,
                        error="content is required for log matching",
                        trace_id=trace_id,
                    )

                # 解析日志内容（简化处理，假设是JSON格式）
                import json
                try:
                    events = json.loads(input_data.content)
                    if not isinstance(events, list):
                        events = [events]
                except json.JSONDecodeError:
                    # 尝试按行解析
                    events = [{"raw": line} for line in input_data.content.split("\n") if line.strip()]

                matches = rule_manager.match_log_events(events, input_data.logsource)

            elif input_data.match_type == "file":
                # 文件匹配
                if not input_data.file_path:
                    return ToolResult(
                        success=False,
                        tool_name=self.name,
                        tool_version=self.version,
                        error="file_path is required for file matching",
                        trace_id=trace_id,
                    )

                matches = rule_manager.match_file(input_data.file_path)

            elif input_data.match_type == "data":
                # 数据匹配
                if not input_data.content:
                    return ToolResult(
                        success=False,
                        tool_name=self.name,
                        tool_version=self.version,
                        error="content is required for data matching",
                        trace_id=trace_id,
                    )

                import base64
                try:
                    data = base64.b64decode(input_data.content)
                except Exception:
                    data = input_data.content.encode("utf-8")

                matches = rule_manager.match_data(data)

            else:
                return ToolResult(
                    success=False,
                    tool_name=self.name,
                    tool_version=self.version,
                    error=f"Invalid match_type: {input_data.match_type}",
                    trace_id=trace_id,
                )

            # 过滤规则类型
            if input_data.rule_type and input_data.rule_type != "all":
                matches = [m for m in matches if m.rule_type == input_data.rule_type]

            execution_time = int((time.time() - start_time) * 1000)

            # 构建结果
            result_data = {
                "match_type": input_data.match_type,
                "total_matches": len(matches),
                "matches": [
                    {
                        "rule_type": m.rule_type,
                        "rule_name": m.rule_name,
                        "rule_id": m.rule_id,
                        "description": m.description,
                        "severity": m.severity,
                        "confidence": m.confidence,
                        "matched_conditions": m.matched_conditions,
                        "recommendations": m.recommendations,
                    }
                    for m in matches
                ],
                "summary": self._generate_summary(matches),
            }

            # 计算总体置信度
            avg_confidence = (
                sum(m.confidence for m in matches) / len(matches) if matches else 0.0
            )

            return ToolResult(
                success=True,
                tool_name=self.name,
                tool_version=self.version,
                data=result_data,
                confidence=avg_confidence,
                evidence_source=["sigma_rules", "yara_rules"],
                trace_id=trace_id,
                execution_time_ms=execution_time,
            )

        except Exception as e:
            logger.error("Rule matching failed: %s", e)
            return ToolResult(
                success=False,
                tool_name=self.name,
                tool_version=self.version,
                error=str(e),
                trace_id=trace_id,
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

    def _generate_summary(self, matches: list) -> str:
        """生成匹配摘要"""
        if not matches:
            return "未检测到威胁"

        critical = sum(1 for m in matches if m.severity == "critical")
        high = sum(1 for m in matches if m.severity == "high")
        medium = sum(1 for m in matches if m.severity == "medium")
        low = sum(1 for m in matches if m.severity == "low")

        parts = []
        if critical:
            parts.append(f"{critical}个关键威胁")
        if high:
            parts.append(f"{high}个高危威胁")
        if medium:
            parts.append(f"{medium}个中危威胁")
        if low:
            parts.append(f"{low}个低危威胁")

        return f"检测到{len(matches)}个威胁: {', '.join(parts)}"


# 创建工具实例
rule_match_tool = RuleMatchTool()
