"""Planner Agent — Generates execution plans for complex tasks.

规划Agent：分析任务需求，生成最优执行计划。
"""

from __future__ import annotations

import logging
from typing import Any

from app.multi_agent.base_agent import BaseAgent
from app.multi_agent.protocol import (
    AgentRole,
    ExecutionPlan,
    PlanStep,
    TaskRequest,
    TaskResult,
)

logger = logging.getLogger(__name__)


class PlannerAgent(BaseAgent):
    """规划Agent — 负责任务分析和执行计划生成"""

    def __init__(
        self,
        agent_id: str = "planner",
        llm_router: Any = None,
        tool_registry: Any = None,
    ):
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.PLANNER,
            llm_router=llm_router,
            tool_registry=tool_registry,
            capabilities=[
                "task_analysis",
                "plan_generation",
                "resource_estimation",
                "dependency_analysis",
            ],
        )

    async def execute_task(self, task: TaskRequest) -> TaskResult:
        """执行规划任务"""
        try:
            # 分析任务类型
            task_type = task.task_type
            context = task.context

            # 根据任务类型选择规划策略
            if task_type == "plan_security_assessment":
                plan = await self._plan_security_assessment(task)
            elif task_type == "plan_incident_response":
                plan = await self._plan_incident_response(task)
            elif task_type == "plan_threat_hunting":
                plan = await self._plan_threat_hunting(task)
            else:
                plan = await self._plan_generic(task)

            return TaskResult(
                task_id=task.task_id,
                success=True,
                result={
                    "plan": plan.model_dump(),
                    "estimated_time_ms": plan.estimated_time_ms,
                    "step_count": len(plan.steps),
                },
                agent_id=self.agent_id,
            )

        except Exception as e:
            logger.error("Planner task failed: %s", e)
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error=str(e),
                agent_id=self.agent_id,
            )

    async def _plan_security_assessment(self, task: TaskRequest) -> ExecutionPlan:
        """规划安全评估任务"""
        target = task.parameters.get("target", "")
        scope = task.parameters.get("scope", "full")

        steps = []

        # 1. 资产发现
        steps.append(PlanStep(
            step_id=1,
            agent_role=AgentRole.EXECUTOR,
            action="asset_discovery",
            parameters={"target": target, "method": "passive"},
        ))

        # 2. 端口扫描
        steps.append(PlanStep(
            step_id=2,
            agent_role=AgentRole.EXECUTOR,
            action="port_scan",
            parameters={"target": target},
            depends_on=[1],
        ))

        # 3. 服务识别
        steps.append(PlanStep(
            step_id=3,
            agent_role=AgentRole.EXECUTOR,
            action="service_enumeration",
            parameters={"target": target},
            depends_on=[2],
        ))

        # 4. 漏洞扫描
        steps.append(PlanStep(
            step_id=4,
            agent_role=AgentRole.EXECUTOR,
            action="vulnerability_scan",
            parameters={"target": target},
            depends_on=[3],
        ))

        # 5. 风险分析
        steps.append(PlanStep(
            step_id=5,
            agent_role=AgentRole.ANALYZER,
            action="risk_analysis",
            parameters={},
            depends_on=[4],
        ))

        # 6. 报告生成
        steps.append(PlanStep(
            step_id=6,
            agent_role=AgentRole.RESPONDER,
            action="generate_assessment_report",
            parameters={"format": "markdown"},
            depends_on=[5],
        ))

        return ExecutionPlan(
            task_request=task,
            steps=steps,
            estimated_time_ms=300000,  # 5分钟
        )

    async def _plan_incident_response(self, task: TaskRequest) -> ExecutionPlan:
        """规划应急响应任务"""
        steps = [
            PlanStep(
                step_id=1,
                agent_role=AgentRole.ANALYZER,
                action="collect_evidence",
                parameters=task.parameters,
            ),
            PlanStep(
                step_id=2,
                agent_role=AgentRole.ANALYZER,
                action="analyze_attack_vector",
                parameters={},
                depends_on=[1],
            ),
            PlanStep(
                step_id=3,
                agent_role=AgentRole.EXECUTOR,
                action="contain_threat",
                parameters={},
                depends_on=[2],
            ),
            PlanStep(
                step_id=4,
                agent_role=AgentRole.EXECUTOR,
                action="eradicate_threat",
                parameters={},
                depends_on=[3],
            ),
            PlanStep(
                step_id=5,
                agent_role=AgentRole.RESPONDER,
                action="generate_incident_report",
                parameters={},
                depends_on=[1, 2, 3, 4],
            ),
        ]

        return ExecutionPlan(
            task_request=task,
            steps=steps,
            estimated_time_ms=600000,  # 10分钟
        )

    async def _plan_threat_hunting(self, task: TaskRequest) -> ExecutionPlan:
        """规划威胁狩猎任务"""
        hypothesis = task.parameters.get("hypothesis", "")

        steps = [
            PlanStep(
                step_id=1,
                agent_role=AgentRole.ANALYZER,
                action="define_hypothesis",
                parameters={"hypothesis": hypothesis},
            ),
            PlanStep(
                step_id=2,
                agent_role=AgentRole.EXECUTOR,
                action="collect_telemetry",
                parameters={},
                depends_on=[1],
            ),
            PlanStep(
                step_id=3,
                agent_role=AgentRole.ANALYZER,
                action="analyze_patterns",
                parameters={},
                depends_on=[2],
            ),
            PlanStep(
                step_id=4,
                agent_role=AgentRole.EXECUTOR,
                action="validate_findings",
                parameters={},
                depends_on=[3],
            ),
            PlanStep(
                step_id=5,
                agent_role=AgentRole.RESPONDER,
                action="generate_hunting_report",
                parameters={},
                depends_on=[4],
            ),
        ]

        return ExecutionPlan(
            task_request=task,
            steps=steps,
            estimated_time_ms=480000,  # 8分钟
        )

    async def _plan_generic(self, task: TaskRequest) -> ExecutionPlan:
        """通用任务规划"""
        steps = [
            PlanStep(
                step_id=1,
                agent_role=AgentRole.ANALYZER,
                action="analyze_task",
                parameters={"description": task.description},
            ),
            PlanStep(
                step_id=2,
                agent_role=AgentRole.EXECUTOR,
                action="execute_main_action",
                parameters=task.parameters,
                depends_on=[1],
            ),
            PlanStep(
                step_id=3,
                agent_role=AgentRole.RESPONDER,
                action="generate_response",
                parameters={},
                depends_on=[2],
            ),
        ]

        return ExecutionPlan(
            task_request=task,
            steps=steps,
            estimated_time_ms=180000,  # 3分钟
        )

    async def estimate_resources(self, task: TaskRequest) -> dict[str, Any]:
        """估算任务所需资源"""
        plan = await self._plan_generic(task)

        return {
            "estimated_time_ms": plan.estimated_time_ms,
            "required_agents": list(set(s.agent_role.value for s in plan.steps)),
            "step_count": len(plan.steps),
            "parallelizable_steps": self._find_parallelizable_steps(plan),
        }

    def _find_parallelizable_steps(self, plan: ExecutionPlan) -> list[list[int]]:
        """找出可以并行执行的步骤组"""
        groups = []
        current_group = []

        for step in plan.steps:
            if not step.depends_on:
                current_group.append(step.step_id)
            else:
                if current_group:
                    groups.append(current_group)
                    current_group = []

        if current_group:
            groups.append(current_group)

        return groups
