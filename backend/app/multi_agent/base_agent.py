"""Base Agent — Abstract base class for all agents.

所有Agent的基类，定义通用接口和生命周期。
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, Optional

from app.multi_agent.protocol import (
    AgentMessage,
    AgentRole,
    MessageType,
    TaskRequest,
    TaskResult,
)
from app.multi_agent.registry import agent_registry

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Agent基类"""

    def __init__(
        self,
        agent_id: str,
        role: AgentRole,
        llm_router: Any = None,
        tool_registry: Any = None,
        capabilities: list[str] | None = None,
    ):
        self.agent_id = agent_id
        self.role = role
        self.llm = llm_router
        self.tools = tool_registry
        self.capabilities = capabilities or []
        self._message_queue: asyncio.Queue[AgentMessage] = asyncio.Queue()
        self._running = False
        self._current_task: Optional[str] = None

        # 注册到全局注册表
        agent_registry.register(agent_id, role, self.capabilities)

    async def start(self) -> None:
        """启动Agent消息处理循环"""
        self._running = True
        logger.info("Agent '%s' started", self.agent_id)

        while self._running:
            try:
                message = await asyncio.wait_for(
                    self._message_queue.get(), timeout=1.0
                )
                await self._handle_message(message)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("Agent '%s' error: %s", self.agent_id, e)

    async def stop(self) -> None:
        """停止Agent"""
        self._running = False
        agent_registry.unregister(self.agent_id)
        logger.info("Agent '%s' stopped", self.agent_id)

    async def send_message(self, message: AgentMessage) -> None:
        """发送消息到目标Agent"""
        # 通过消息总线分发
        await message_bus.dispatch(message)

    async def receive_message(self, message: AgentMessage) -> None:
        """接收消息（放入队列）"""
        await self._message_queue.put(message)

    async def _handle_message(self, message: AgentMessage) -> None:
        """处理接收到的消息"""
        logger.debug(
            "Agent '%s' received message from '%s', type=%s",
            self.agent_id,
            message.sender,
            message.message_type.value,
        )

        # 更新心跳
        agent_registry.heartbeat(self.agent_id)

        # 根据消息类型分发
        if message.message_type == MessageType.TASK_REQUEST:
            task_request = TaskRequest(**message.content)
            result = await self.execute_task(task_request)
            reply = message.create_reply(
                sender=self.agent_id,
                content=result.model_dump(),
            )
            reply.message_type = MessageType.TASK_RESULT
            await self.send_message(reply)

        elif message.message_type == MessageType.QUERY:
            response = await self.handle_query(message.content)
            reply = message.create_reply(
                sender=self.agent_id,
                content=response,
            )
            await self.send_message(reply)

        elif message.message_type == MessageType.SHUTDOWN:
            await self.stop()

    @abstractmethod
    async def execute_task(self, task: TaskRequest) -> TaskResult:
        """执行任务（子类必须实现）"""
        ...

    async def handle_query(self, query: dict[str, Any]) -> dict[str, Any]:
        """处理查询请求（子类可覆盖）"""
        return {"status": "not_implemented"}

    def update_load(self, load: float) -> None:
        """更新负载"""
        agent_registry.update_status(
            self.agent_id,
            status="busy" if load > 0.5 else "idle",
            current_task=self._current_task,
            load=load,
        )


class MessageBus:
    """消息总线 — 管理Agent间消息路由"""

    def __init__(self):
        self._agents: dict[str, BaseAgent] = {}

    def register_agent(self, agent: BaseAgent) -> None:
        """注册Agent到消息总线"""
        self._agents[agent.agent_id] = agent
        logger.info("Agent '%s' registered to message bus", agent.agent_id)

    def unregister_agent(self, agent_id: str) -> None:
        """从消息总线注销Agent"""
        self._agents.pop(agent_id, None)

    def get_agent(self, agent_id: str) -> BaseAgent | None:
        """Return a registered agent instance if it exists."""
        return self._agents.get(agent_id)

    async def dispatch(self, message: AgentMessage) -> None:
        """分发消息到目标Agent"""
        target = message.receiver

        if target == "broadcast":
            # 广播给所有Agent（除发送者）
            for agent_id, agent in self._agents.items():
                if agent_id != message.sender:
                    await agent.receive_message(message)
            return

        if target in self._agents:
            await self._agents[target].receive_message(message)
        else:
            logger.warning("Target agent '%s' not found", target)

    async def send_to_role(self, role: AgentRole, message: AgentMessage) -> None:
        """发送消息给指定角色的所有Agent"""
        for agent_id, agent in self._agents.items():
            if agent.role == role and agent_id != message.sender:
                await agent.receive_message(message)

    def list_agents(self) -> list[str]:
        """列出所有注册的Agent"""
        return list(self._agents.keys())


# 全局消息总线
message_bus = MessageBus()
