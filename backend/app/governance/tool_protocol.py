"""
Tool Protocol — 代码实现。

规范定义见 docs/agent/governance/tool_protocol.md
"""

import uuid
from typing import Any, Optional

from pydantic import BaseModel, Field


class ToolInput(BaseModel):
    """所有 Tool 输入必须继承此类"""

    trace_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="请求追踪 ID",
    )
    tenant_id: str = Field(..., description="租户 ID，不可为空")
    timeout: int = Field(default=30, ge=1, le=300, description="超时秒数")
    tool_version: str = Field(default="v1", description="Tool Schema 版本")


class ToolResult(BaseModel):
    """所有 Tool 输出必须使用此类"""

    success: bool = Field(..., description="是否执行成功")
    tool_name: str = Field(..., description="Tool 名称")
    tool_version: str = Field(..., description="Tool Schema 版本")
    data: dict[str, Any] = Field(default_factory=dict, description="返回数据")
    error: Optional[str] = Field(default=None, description="错误信息")
    confidence: float = Field(
        default=0.0, ge=0.0, le=1.0, description="结果置信度 0.0-1.0"
    )
    evidence_source: list[str] = Field(
        default_factory=list, description="数据来源列表"
    )
    trace_id: str = Field(
        ..., description="请求追踪 ID，与 ToolInput.trace_id 对应"
    )
    execution_time_ms: int = Field(
        default=0, ge=0, description="执行耗时毫秒"
    )
