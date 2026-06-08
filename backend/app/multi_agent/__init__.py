"""Multi-Agent Collaboration Framework.

支持多智能体协同工作，包括：
- 协调者 (Coordinator): 任务分解与调度
- 规划Agent (Planner): 生成执行计划
- 分析Agent (Analyzer): 深度数据分析
- 响应Agent (Responder): 生成最终响应
"""

from app.multi_agent.protocol import AgentMessage, MessageType, TaskRequest
from app.multi_agent.coordinator import Coordinator
from app.multi_agent.registry import AgentRegistry

__all__ = [
    "AgentMessage",
    "MessageType",
    "TaskRequest",
    "Coordinator",
    "AgentRegistry",
]
