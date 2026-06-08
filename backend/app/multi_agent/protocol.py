"""Multi-Agent Communication Protocol.

定义Agent间消息传递的标准格式和类型。
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class MessageType(str, Enum):
    """消息类型枚举"""
    # 任务相关
    TASK_REQUEST = "task_request"          # 任务请求
    TASK_ASSIGN = "task_assign"            # 任务分配
    TASK_RESULT = "task_result"            # 任务结果
    TASK_ERROR = "task_error"              # 任务错误

    # 协作相关
    QUERY = "query"                        # 查询请求
    RESPONSE = "response"                  # 查询响应
    BROADCAST = "broadcast"                # 广播消息

    # 控制相关
    HEARTBEAT = "heartbeat"                # 心跳检测
    STATUS_UPDATE = "status_update"        # 状态更新
    SHUTDOWN = "shutdown"                  # 关闭信号


class AgentRole(str, Enum):
    """Agent角色枚举"""
    COORDINATOR = "coordinator"            # 协调者
    PLANNER = "planner"                    # 规划者
    ANALYZER = "analyzer"                  # 分析者
    RESPONDER = "responder"                # 响应者
    EXECUTOR = "executor"                  # 执行者


class TaskPriority(str, Enum):
    """任务优先级"""
    CRITICAL = "critical"                  # 紧急
    HIGH = "high"                          # 高
    MEDIUM = "medium"                      # 中
    LOW = "low"                            # 低


class AgentMessage(BaseModel):
    """Agent间通信消息"""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sender: str = Field(..., description="发送者Agent ID")
    receiver: str = Field(..., description="接收者Agent ID")
    message_type: MessageType = Field(..., description="消息类型")
    content: dict[str, Any] = Field(default_factory=dict, description="消息内容")
    metadata: dict[str, Any] = Field(default_factory=dict, description="元数据")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: Optional[str] = Field(default=None, description="关联ID，用于追踪请求-响应")
    reply_to: Optional[str] = Field(default=None, description="回复目标消息ID")

    def create_reply(self, sender: str, content: dict[str, Any]) -> AgentMessage:
        """创建回复消息"""
        return AgentMessage(
            sender=sender,
            receiver=self.sender,
            message_type=MessageType.RESPONSE,
            content=content,
            correlation_id=self.message_id,
            reply_to=self.message_id,
        )


class TaskRequest(BaseModel):
    """任务请求"""
    task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    task_type: str = Field(..., description="任务类型")
    description: str = Field(..., description="任务描述")
    parameters: dict[str, Any] = Field(default_factory=dict, description="任务参数")
    priority: TaskPriority = Field(default=TaskPriority.MEDIUM)
    deadline_seconds: Optional[int] = Field(default=None, description="截止时间（秒）")
    dependencies: list[str] = Field(default_factory=list, description="依赖的任务ID")
    context: dict[str, Any] = Field(default_factory=dict, description="上下文信息")


class TaskResult(BaseModel):
    """任务结果"""
    task_id: str = Field(..., description="任务ID")
    success: bool = Field(..., description="是否成功")
    result: dict[str, Any] = Field(default_factory=dict, description="结果数据")
    error: Optional[str] = Field(default=None, description="错误信息")
    execution_time_ms: int = Field(default=0, description="执行耗时（毫秒）")
    agent_id: str = Field(..., description="执行Agent ID")
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentStatus(BaseModel):
    """Agent状态"""
    agent_id: str = Field(..., description="Agent ID")
    role: AgentRole = Field(..., description="Agent角色")
    status: str = Field(default="idle", description="状态: idle/busy/error")
    current_task: Optional[str] = Field(default=None, description="当前任务ID")
    capabilities: list[str] = Field(default_factory=list, description="能力列表")
    load: float = Field(default=0.0, ge=0.0, le=1.0, description="负载率 0-1")
    last_heartbeat: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ExecutionPlan(BaseModel):
    """执行计划"""
    plan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    task_request: TaskRequest = Field(..., description="原始任务请求")
    steps: list[PlanStep] = Field(default_factory=list, description="执行步骤")
    estimated_time_ms: int = Field(default=0, description="预估执行时间")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PlanStep(BaseModel):
    """计划步骤"""
    step_id: int = Field(..., description="步骤序号")
    agent_role: AgentRole = Field(..., description="执行Agent角色")
    action: str = Field(..., description="执行动作")
    parameters: dict[str, Any] = Field(default_factory=dict)
    depends_on: list[int] = Field(default_factory=list, description="依赖的步骤序号")
    optional: bool = Field(default=False, description="是否可选")
