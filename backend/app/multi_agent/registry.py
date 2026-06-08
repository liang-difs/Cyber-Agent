"""Agent Registry — Centralized agent registration and discovery.

管理所有Agent的注册、发现和状态。
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from app.multi_agent.protocol import AgentRole, AgentStatus

logger = logging.getLogger(__name__)


class AgentRegistry:
    """Agent注册表，管理所有Agent实例"""

    def __init__(self):
        self._agents: dict[str, AgentStatus] = {}
        self._role_agents: dict[AgentRole, list[str]] = {role: [] for role in AgentRole}

    def register(self, agent_id: str, role: AgentRole, capabilities: list[str] | None = None) -> None:
        """注册Agent"""
        if agent_id in self._agents:
            logger.warning("Agent '%s' already registered, updating", agent_id)

        status = AgentStatus(
            agent_id=agent_id,
            role=role,
            status="idle",
            capabilities=capabilities or [],
        )
        self._agents[agent_id] = status

        # 按角色索引
        if agent_id not in self._role_agents[role]:
            self._role_agents[role].append(agent_id)

        logger.info("Agent '%s' registered with role '%s'", agent_id, role.value)

    def unregister(self, agent_id: str) -> None:
        """注销Agent"""
        if agent_id not in self._agents:
            return

        status = self._agents.pop(agent_id)
        if agent_id in self._role_agents[status.role]:
            self._role_agents[status.role].remove(agent_id)

        logger.info("Agent '%s' unregistered", agent_id)

    def get(self, agent_id: str) -> Optional[AgentStatus]:
        """获取Agent状态"""
        return self._agents.get(agent_id)

    def get_by_role(self, role: AgentRole) -> list[AgentStatus]:
        """按角色获取Agent列表"""
        agent_ids = self._role_agents.get(role, [])
        return [self._agents[aid] for aid in agent_ids if aid in self._agents]

    def get_available_by_role(self, role: AgentRole) -> Optional[AgentStatus]:
        """获取指定角色的可用Agent（负载最低）"""
        agents = self.get_by_role(role)
        available = [a for a in agents if a.status == "idle" or a.load < 0.8]

        if not available:
            return None

        # 返回负载最低的
        return min(available, key=lambda a: a.load)

    def update_status(
        self,
        agent_id: str,
        status: str = "idle",
        current_task: Optional[str] = None,
        load: Optional[float] = None,
    ) -> None:
        """更新Agent状态"""
        if agent_id not in self._agents:
            logger.warning("Agent '%s' not found", agent_id)
            return

        agent = self._agents[agent_id]
        agent.status = status
        if current_task is not None:
            agent.current_task = current_task
        if load is not None:
            agent.load = load
        agent.last_heartbeat = datetime.now(timezone.utc)

    def heartbeat(self, agent_id: str) -> None:
        """更新心跳时间"""
        if agent_id in self._agents:
            self._agents[agent_id].last_heartbeat = datetime.now(timezone.utc)

    def list_all(self) -> list[AgentStatus]:
        """列出所有Agent"""
        return list(self._agents.values())

    def list_by_capability(self, capability: str) -> list[AgentStatus]:
        """按能力查找Agent"""
        return [a for a in self._agents.values() if capability in a.capabilities]

    def get_stats(self) -> dict[str, Any]:
        """获取统计信息"""
        total = len(self._agents)
        by_status = {}
        by_role = {}

        for agent in self._agents.values():
            by_status[agent.status] = by_status.get(agent.status, 0) + 1
            by_role[agent.role.value] = by_role.get(agent.role.value, 0) + 1

        return {
            "total_agents": total,
            "by_status": by_status,
            "by_role": by_role,
            "average_load": sum(a.load for a in self._agents.values()) / max(total, 1),
        }


# 全局Agent注册表
agent_registry = AgentRegistry()
