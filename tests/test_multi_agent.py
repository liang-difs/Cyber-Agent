"""Tests for Multi-Agent Collaboration Framework.

测试多智能体协同框架的核心功能。
"""

import pytest
import asyncio

from app.multi_agent.protocol import (
    AgentMessage,
    AgentRole,
    MessageType,
    TaskRequest,
    TaskResult,
    TaskPriority,
)
from app.multi_agent.registry import AgentRegistry
from app.multi_agent.base_agent import message_bus
from app.multi_agent.analyzer_agent import AnalyzerAgent
from app.multi_agent.executor_agent import ExecutorAgent
from app.multi_agent.coordinator import Coordinator
from app.multi_agent.responder_agent import ResponderAgent


@pytest.fixture
def registry():
    """创建测试用的Agent注册表"""
    return AgentRegistry()


@pytest.fixture
def coordinator():
    """创建测试用的协调者"""
    return Coordinator(agent_id="test_coordinator")


class TestAgentRegistry:
    """测试Agent注册表"""

    def test_register_agent(self, registry):
        """测试注册Agent"""
        registry.register("agent_1", AgentRole.ANALYZER, ["log_analysis"])
        agent = registry.get("agent_1")
        assert agent is not None
        assert agent.agent_id == "agent_1"
        assert agent.role == AgentRole.ANALYZER
        assert "log_analysis" in agent.capabilities

    def test_unregister_agent(self, registry):
        """测试注销Agent"""
        registry.register("agent_1", AgentRole.ANALYZER)
        registry.unregister("agent_1")
        assert registry.get("agent_1") is None

    def test_get_by_role(self, registry):
        """测试按角色获取Agent"""
        registry.register("analyzer_1", AgentRole.ANALYZER)
        registry.register("analyzer_2", AgentRole.ANALYZER)
        registry.register("executor_1", AgentRole.EXECUTOR)

        analyzers = registry.get_by_role(AgentRole.ANALYZER)
        assert len(analyzers) == 2

        executors = registry.get_by_role(AgentRole.EXECUTOR)
        assert len(executors) == 1

    def test_get_available_by_role(self, registry):
        """测试获取可用Agent"""
        registry.register("analyzer_1", AgentRole.ANALYZER)
        registry.register("analyzer_2", AgentRole.ANALYZER)

        # 更新负载
        registry.update_status("analyzer_1", load=0.9)
        registry.update_status("analyzer_2", load=0.2)

        # 应该返回负载最低的
        available = registry.get_available_by_role(AgentRole.ANALYZER)
        assert available is not None
        assert available.agent_id == "analyzer_2"

    def test_list_by_capability(self, registry):
        """测试按能力查找Agent"""
        registry.register("agent_1", AgentRole.ANALYZER, ["log_analysis", "traffic_analysis"])
        registry.register("agent_2", AgentRole.EXECUTOR, ["port_scan"])

        agents = registry.list_by_capability("log_analysis")
        assert len(agents) == 1
        assert agents[0].agent_id == "agent_1"

    def test_get_stats(self, registry):
        """测试获取统计信息"""
        registry.register("agent_1", AgentRole.ANALYZER)
        registry.register("agent_2", AgentRole.EXECUTOR)

        stats = registry.get_stats()
        assert stats["total_agents"] == 2
        assert "analyzer" in stats["by_role"]
        assert "executor" in stats["by_role"]


class TestAgentMessage:
    """测试Agent消息"""

    def test_create_message(self):
        """测试创建消息"""
        msg = AgentMessage(
            sender="coordinator",
            receiver="analyzer",
            message_type=MessageType.TASK_REQUEST,
            content={"task_type": "test"},
        )
        assert msg.sender == "coordinator"
        assert msg.receiver == "analyzer"
        assert msg.message_type == MessageType.TASK_REQUEST

    def test_create_reply(self):
        """测试创建回复"""
        original = AgentMessage(
            sender="coordinator",
            receiver="analyzer",
            message_type=MessageType.QUERY,
            content={"question": "test"},
        )

        reply = original.create_reply(
            sender="analyzer",
            content={"answer": "result"},
        )
        assert reply.sender == "analyzer"
        assert reply.receiver == "coordinator"
        assert reply.reply_to == original.message_id


class TestTaskRequest:
    """测试任务请求"""

    def test_create_task_request(self):
        """测试创建任务请求"""
        task = TaskRequest(
            task_type="incident_response",
            description="Test incident",
            parameters={"target": "192.168.1.1"},
            priority=TaskPriority.HIGH,
        )
        assert task.task_type == "incident_response"
        assert task.priority == TaskPriority.HIGH

    def test_task_request_defaults(self):
        """测试任务请求默认值"""
        task = TaskRequest(
            task_type="test",
            description="Test task",
        )
        assert task.priority == TaskPriority.MEDIUM
        assert task.parameters == {}
        assert task.dependencies == []


class TestCoordinator:
    """测试协调者"""

    def test_plan_incident_response(self, coordinator):
        """测试应急响应计划"""
        task = TaskRequest(
            task_type="incident_response",
            description="Test incident",
        )

        steps = coordinator._plan_incident_response(task)
        assert len(steps) == 4
        assert steps[0].action == "analyze_logs"
        assert steps[1].depends_on == [1]

    def test_plan_penetration_test(self, coordinator):
        """测试渗透测试计划"""
        task = TaskRequest(
            task_type="penetration_test",
            description="Test pentest",
            parameters={"target": "192.168.1.1"},
        )

        steps = coordinator._plan_penetration_test(task)
        assert len(steps) == 5
        assert steps[0].action == "port_scan"

    def test_plan_threat_hunting(self, coordinator):
        """测试威胁狩猎计划"""
        task = TaskRequest(
            task_type="threat_hunting",
            description="Test hunting",
        )

        steps = coordinator._plan_threat_hunting(task)
        assert len(steps) == 4
        assert steps[0].action == "analyze_network_traffic"

    def test_plan_malware_analysis(self, coordinator):
        """测试恶意软件分析计划"""
        task = TaskRequest(
            task_type="malware_analysis",
            description="Test malware",
        )

        steps = coordinator._plan_malware_analysis(task)
        assert len(steps) == 4
        assert steps[0].action == "static_analysis"

    def test_plan_vulnerability_assessment(self, coordinator):
        """测试漏洞评估计划"""
        task = TaskRequest(
            task_type="vulnerability_assessment",
            description="Test vuln assessment",
            parameters={"target": "192.168.1.1"},
        )

        steps = coordinator._plan_vulnerability_assessment(task)
        assert len(steps) == 4
        assert steps[0].action == "asset_discovery"

    def test_coordinator_executes_real_agents(self):
        """End-to-end check that the coordinator waits for actual agent results."""
        analyzer = AnalyzerAgent(agent_id="test_analyzer_closure")
        executor = ExecutorAgent(agent_id="test_executor_closure")
        responder = ResponderAgent(agent_id="test_responder_closure")
        coordinator = Coordinator(agent_id="test_coordinator_closure")

        for agent in (analyzer, executor, responder):
            message_bus.register_agent(agent)

        try:
            task = TaskRequest(
                task_type="incident_response",
                description="Investigate suspicious login activity",
                parameters={
                    "content": "error unauthorized 10.0.0.5 connected to 8.8.8.8",
                    "tenant_id": "tenant-a",
                },
            )

            result = asyncio.run(coordinator.execute_task(task))

            assert result.success is True
            assert result.result["status"] == "completed"
            assert result.result["successful_steps"] == 4
            assert result.result["step_results"][1]["agent"] == analyzer.agent_id
            assert result.result["step_results"][2]["agent"] == analyzer.agent_id
            assert result.result["step_results"][3]["agent"] == executor.agent_id
            assert result.result["step_results"][4]["agent"] == responder.agent_id
            assert "simulated" not in str(result.result).lower()
        finally:
            for agent in (analyzer, executor, responder):
                message_bus.unregister_agent(agent.agent_id)
                asyncio.run(agent.stop())
            asyncio.run(coordinator.stop())


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
