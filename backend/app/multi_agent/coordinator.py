"""Coordinator Agent — Orchestrates multi-agent collaboration.

协调者角色：任务分解、Agent调度、结果聚合。
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from app.multi_agent.base_agent import BaseAgent, message_bus
from app.multi_agent.protocol import (
    AgentMessage,
    AgentRole,
    ExecutionPlan,
    MessageType,
    PlanStep,
    TaskPriority,
    TaskRequest,
    TaskResult,
)
from app.multi_agent.registry import agent_registry

logger = logging.getLogger(__name__)


def _get_decision_tracker():
    """Lazy-load decision tracker singleton."""
    from app.agent.decision_trace import DecisionTracker
    return DecisionTracker()


class Coordinator(BaseAgent):
    """协调者Agent — 负责任务分解和多Agent调度"""

    def __init__(
        self,
        agent_id: str = "coordinator",
        llm_router: Any = None,
        tool_registry: Any = None,
    ):
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.COORDINATOR,
            llm_router=llm_router,
            tool_registry=tool_registry,
            capabilities=["task_decomposition", "agent_scheduling", "result_aggregation"],
        )
        self._pending_tasks: dict[str, TaskRequest] = {}
        self._task_results: dict[str, TaskResult] = {}
        self._execution_plans: dict[str, ExecutionPlan] = {}

    async def execute_task(self, task: TaskRequest) -> TaskResult:
        """执行协调任务"""
        start_time = time.time()
        self._current_task = task.task_id
        self.update_load(0.8)

        try:
            # 1. 分析任务，生成执行计划
            plan = await self._create_execution_plan(task)
            self._execution_plans[plan.plan_id] = plan

            logger.info(
                "Coordinator created plan '%s' with %d steps",
                plan.plan_id,
                len(plan.steps),
            )

            # 追踪：记录计划创建
            tracker = _get_decision_tracker()
            tracker.start_trace(
                trace_id=task.task_id,
                session_id=task.task_id,
                user_id="coordinator",
                tenant_id=task.context.get("tenant_id", "default"),
                query=task.description,
            )
            tracker.add_thought(
                trace_id=task.task_id,
                turn=0,
                thought=f"创建执行计划: {len(plan.steps)} 步, 任务类型: {task.task_type}",
                confidence=0.9,
            )

            # 2. 执行计划
            results = await self._execute_plan(plan)

            # 追踪：记录每步结果
            for step_id, step_result in results.items():
                tracker.add_action(
                    trace_id=task.task_id,
                    turn=step_id,
                    tool_name=step_result.metadata.get("action", "unknown"),
                    tool_input=step_result.metadata.get("parameters", {}),
                    confidence=0.8 if step_result.success else 0.2,
                )
                tracker.add_observation(
                    trace_id=task.task_id,
                    turn=step_id,
                    tool_name=step_result.metadata.get("action", "unknown"),
                    tool_output={"success": step_result.success, "result": str(step_result.result)[:500] if step_result.success else step_result.error},
                    confidence=0.9 if step_result.success else 0.1,
                )

            # 3. 聚合结果
            final_result = await self._aggregate_results(task, results)

            # 追踪：记录最终结果
            tracker.add_final_answer(
                trace_id=task.task_id,
                answer=str(final_result)[:1000],
                confidence=0.85,
            )
            tracker.end_trace(task.task_id, success=True)

            execution_time = int((time.time() - start_time) * 1000)

            return TaskResult(
                task_id=task.task_id,
                success=True,
                result=final_result,
                execution_time_ms=execution_time,
                agent_id=self.agent_id,
                metadata={"plan_id": plan.plan_id, "steps_executed": len(results)},
            )

        except Exception as e:
            logger.error("Coordinator task failed: %s", e)
            return TaskResult(
                task_id=task.task_id,
                success=False,
                error=str(e),
                execution_time_ms=int((time.time() - start_time) * 1000),
                agent_id=self.agent_id,
            )
        finally:
            self._current_task = None
            self.update_load(0.0)

    async def _create_execution_plan(self, task: TaskRequest) -> ExecutionPlan:
        """根据任务类型创建执行计划"""
        task_type = task.task_type.lower()

        # 预定义的任务分解模板
        if task_type == "incident_response":
            steps = self._plan_incident_response(task)
        elif task_type == "penetration_test":
            steps = self._plan_penetration_test(task)
        elif task_type == "threat_hunting":
            steps = self._plan_threat_hunting(task)
        elif task_type == "malware_analysis":
            steps = self._plan_malware_analysis(task)
        elif task_type == "vulnerability_assessment":
            steps = self._plan_vulnerability_assessment(task)
        elif task_type in ("reverse_engineering", "malware_reversing", "binary_analysis"):
            steps = self._plan_reverse_engineering(task)
        else:
            # 通用任务：使用LLM分析并分解
            steps = await self._plan_with_llm(task)

        return ExecutionPlan(
            task_request=task,
            steps=steps,
            estimated_time_ms=sum(60000 for _ in steps),  # 每步预估1分钟
        )

    def _plan_incident_response(self, task: TaskRequest) -> list[PlanStep]:
        """应急响应任务分解"""
        return [
            PlanStep(
                step_id=1,
                agent_role=AgentRole.ANALYZER,
                action="analyze_logs",
                parameters={"source": task.parameters.get("log_source", "system")},
            ),
            PlanStep(
                step_id=2,
                agent_role=AgentRole.ANALYZER,
                action="extract_iocs",
                parameters={},
                depends_on=[1],
            ),
            PlanStep(
                step_id=3,
                agent_role=AgentRole.EXECUTOR,
                action="lookup_threat_intel",
                parameters={},
                depends_on=[2],
            ),
            PlanStep(
                step_id=4,
                agent_role=AgentRole.RESPONDER,
                action="generate_report",
                parameters={"format": "markdown"},
                depends_on=[1, 2, 3],
            ),
        ]

    def _plan_penetration_test(self, task: TaskRequest) -> list[PlanStep]:
        """渗透测试任务分解"""
        target = task.parameters.get("target", "")
        return [
            PlanStep(
                step_id=1,
                agent_role=AgentRole.EXECUTOR,
                action="port_scan",
                parameters={"target": target},
            ),
            PlanStep(
                step_id=2,
                agent_role=AgentRole.EXECUTOR,
                action="service_enumeration",
                parameters={"target": target},
                depends_on=[1],
            ),
            PlanStep(
                step_id=3,
                agent_role=AgentRole.EXECUTOR,
                action="vulnerability_scan",
                parameters={"target": target},
                depends_on=[2],
            ),
            PlanStep(
                step_id=4,
                agent_role=AgentRole.ANALYZER,
                action="analyze_attack_surface",
                parameters={},
                depends_on=[1, 2, 3],
            ),
            PlanStep(
                step_id=5,
                agent_role=AgentRole.RESPONDER,
                action="generate_pentest_report",
                parameters={},
                depends_on=[4],
            ),
        ]

    def _plan_threat_hunting(self, task: TaskRequest) -> list[PlanStep]:
        """威胁狩猎任务分解"""
        return [
            PlanStep(
                step_id=1,
                agent_role=AgentRole.ANALYZER,
                action="analyze_network_traffic",
                parameters=task.parameters,
            ),
            PlanStep(
                step_id=2,
                agent_role=AgentRole.ANALYZER,
                action="detect_anomalies",
                parameters={},
                depends_on=[1],
            ),
            PlanStep(
                step_id=3,
                agent_role=AgentRole.EXECUTOR,
                action="correlate_threat_intel",
                parameters={},
                depends_on=[2],
            ),
            PlanStep(
                step_id=4,
                agent_role=AgentRole.RESPONDER,
                action="generate_hunting_report",
                parameters={},
                depends_on=[1, 2, 3],
            ),
        ]

    def _plan_malware_analysis(self, task: TaskRequest) -> list[PlanStep]:
        """恶意软件分析任务分解"""
        return [
            PlanStep(
                step_id=1,
                agent_role=AgentRole.EXECUTOR,
                action="static_analysis",
                parameters=task.parameters,
            ),
            PlanStep(
                step_id=2,
                agent_role=AgentRole.EXECUTOR,
                action="hash_lookup",
                parameters={},
                depends_on=[1],
            ),
            PlanStep(
                step_id=3,
                agent_role=AgentRole.ANALYZER,
                action="behavior_analysis",
                parameters={},
                depends_on=[1],
            ),
            PlanStep(
                step_id=4,
                agent_role=AgentRole.RESPONDER,
                action="generate_malware_report",
                parameters={},
                depends_on=[1, 2, 3],
            ),
        ]

    def _plan_vulnerability_assessment(self, task: TaskRequest) -> list[PlanStep]:
        """漏洞评估任务分解"""
        target = task.parameters.get("target", "")
        return [
            PlanStep(
                step_id=1,
                agent_role=AgentRole.EXECUTOR,
                action="asset_discovery",
                parameters={"target": target},
            ),
            PlanStep(
                step_id=2,
                agent_role=AgentRole.EXECUTOR,
                action="vulnerability_scan",
                parameters={"target": target},
                depends_on=[1],
            ),
            PlanStep(
                step_id=3,
                agent_role=AgentRole.ANALYZER,
                action="risk_assessment",
                parameters={},
                depends_on=[1, 2],
            ),
            PlanStep(
                step_id=4,
                agent_role=AgentRole.RESPONDER,
                action="generate_vuln_report",
                parameters={},
                depends_on=[3],
            ),
        ]

    async def _plan_with_llm(self, task: TaskRequest) -> list[PlanStep]:
        """使用LLM生成动态执行计划（通用任务）"""
        # 先尝试 LLM 动态规划
        try:
            if self.llm_router:
                plan = await self._llm_generate_plan(task)
                if plan:
                    return plan
        except Exception as e:
            logger.warning("LLM planning failed, falling back to template: %s", e)

        # 降级：通用三步模板
        return [
            PlanStep(
                step_id=1,
                agent_role=AgentRole.ANALYZER,
                action="analyze_task",
                parameters={"description": task.description},
            ),
            PlanStep(
                step_id=2,
                agent_role=AgentRole.EXECUTOR,
                action="execute_action",
                parameters=task.parameters,
                depends_on=[1],
            ),
            PlanStep(
                step_id=3,
                agent_role=AgentRole.RESPONDER,
                action="generate_response",
                parameters={},
                depends_on=[1, 2],
            ),
        ]

    async def _llm_generate_plan(self, task: TaskRequest) -> list[PlanStep] | None:
        """调用 LLM 生成动态执行计划"""
        from app.llm.router import LLMRequest

        available_actions = {
            "ANALYZER": [
                "analyze_logs", "analyze_network_traffic", "detect_anomalies",
                "extract_iocs", "behavior_analysis", "risk_assessment",
                "analyze_attack_surface", "analyze_task",
            ],
            "EXECUTOR": [
                "port_scan", "service_enumeration", "vulnerability_scan",
                "asset_discovery", "lookup_threat_intel", "static_analysis",
                "hash_lookup", "execute_action",
            ],
            "RESPONDER": [
                "generate_report", "generate_pentest_report",
                "generate_hunting_report", "generate_malware_report",
                "generate_vuln_report", "generate_response",
            ],
        }

        prompt = f"""你是安全任务规划器。根据任务描述生成执行计划。

任务类型: {task.task_type}
任务描述: {task.description}
参数: {task.parameters}
上下文: {task.context}

可用角色和动作:
{chr(10).join(f'  {role}: {", ".join(actions)}' for role, actions in available_actions.items())}

请生成 JSON 格式的执行计划，包含 2-6 个步骤:
```json
[
  {{"step": 1, "role": "ANALYZER", "action": "...", "params": {{}}, "depends_on": []}},
  {{"step": 2, "role": "EXECUTOR", "action": "...", "params": {{}}, "depends_on": [1]}}
]
```

要求:
1. 步骤之间有合理的依赖关系
2. 参数中引用任务的具体目标
3. 最后一步必须是 RESPONDER 生成报告
4. 只输出 JSON 数组，不要其他内容"""

        request = LLMRequest(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=1024,
            trace_id=task.task_id,
        )

        response = await self.llm_router.complete(request)
        content = response.content.strip()

        # 解析 JSON
        import json
        import re

        json_match = re.search(r'\[.*\]', content, re.DOTALL)
        if not json_match:
            return None

        steps_data = json.loads(json_match.group())

        role_map = {
            "ANALYZER": AgentRole.ANALYZER,
            "EXECUTOR": AgentRole.EXECUTOR,
            "RESPONDER": AgentRole.RESPONDER,
        }

        steps = []
        for item in steps_data:
            role = role_map.get(item.get("role", "").upper())
            if not role:
                continue
            steps.append(PlanStep(
                step_id=item.get("step", len(steps) + 1),
                agent_role=role,
                action=item.get("action", "execute_action"),
                parameters=item.get("params", {}),
                depends_on=item.get("depends_on", []),
            ))

        return steps if len(steps) >= 2 else None

    def _plan_reverse_engineering(self, task: TaskRequest) -> list[PlanStep]:
        """逆向工程任务分解"""
        return [
            PlanStep(
                step_id=1,
                agent_role=AgentRole.EXECUTOR,
                action="static_analysis",
                parameters=task.parameters,
            ),
            PlanStep(
                step_id=2,
                agent_role=AgentRole.EXECUTOR,
                action="hash_lookup",
                parameters={},
                depends_on=[1],
            ),
            PlanStep(
                step_id=3,
                agent_role=AgentRole.ANALYZER,
                action="behavior_analysis",
                parameters={},
                depends_on=[1],
            ),
            PlanStep(
                step_id=4,
                agent_role=AgentRole.ANALYZER,
                action="extract_iocs",
                parameters={},
                depends_on=[1, 2, 3],
            ),
            PlanStep(
                step_id=5,
                agent_role=AgentRole.RESPONDER,
                action="generate_report",
                parameters={"format": "markdown"},
                depends_on=[1, 2, 3, 4],
            ),
        ]

    def _collect_dependency_results(
        self, step: PlanStep, results: dict[int, TaskResult]
    ) -> list[dict[str, Any]]:
        """Collect structured dependency outputs for a step."""
        dependency_results: list[dict[str, Any]] = []
        for dependency_id in step.depends_on:
            dependency = results.get(dependency_id)
            if not dependency:
                continue
            dependency_results.append(
                {
                    "step_id": dependency_id,
                    "agent_id": dependency.agent_id,
                    "success": dependency.success,
                    "result": dependency.result,
                    "error": dependency.error,
                    "execution_time_ms": dependency.execution_time_ms,
                }
            )
        return dependency_results

    def _flatten_values(self, value: Any) -> list[Any]:
        """Flatten a value into a simple list when possible."""
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, (tuple, set)):
            return list(value)
        return [value]

    def _collect_nested_values(self, payloads: list[dict[str, Any]], keys: tuple[str, ...]) -> list[Any]:
        """Collect values from dependency payloads using a set of keys."""
        values: list[Any] = []
        for payload in payloads:
            for key in keys:
                if key not in payload:
                    continue
                collected = payload.get(key)
                if key == "iocs" and isinstance(collected, dict):
                    for nested in collected.values():
                        values.extend(self._flatten_values(nested))
                    continue
                values.extend(self._flatten_values(collected))
        return values

    def _compose_dependency_summary(self, dependency_results: list[dict[str, Any]]) -> str:
        """Create a short human-readable summary for downstream agents."""
        if not dependency_results:
            return "No dependency results available."

        parts: list[str] = []
        for dependency in dependency_results:
            status = "success" if dependency["success"] else "failed"
            parts.append(f"step {dependency['step_id']} via {dependency['agent_id']} ({status})")
        return "; ".join(parts)

    def _infer_risk_level(self, dependency_results: list[dict[str, Any]]) -> str:
        """Infer a coarse risk label from dependency output."""
        for dependency in dependency_results:
            payload = dependency.get("result")
            if not isinstance(payload, dict):
                continue
            for key in ("overall_risk", "threat_level", "risk_level"):
                level = payload.get(key)
                if isinstance(level, str) and level:
                    return level
        return "medium"

    def _build_assessment_context(
        self,
        dependency_payloads: list[dict[str, Any]],
        dependency_results: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Compose a compact assessment payload for reporting."""
        vulnerabilities = self._collect_nested_values(dependency_payloads, ("vulnerabilities", "findings"))
        assets = self._collect_nested_values(dependency_payloads, ("assets", "discovered_assets"))
        risk_scores = self._collect_nested_values(dependency_payloads, ("risk_scores",))

        return {
            "asset_count": len(assets),
            "critical_vulns": sum(
                1 for vuln in vulnerabilities if isinstance(vuln, dict) and vuln.get("severity") == "critical"
            ),
            "high_vulns": sum(
                1 for vuln in vulnerabilities if isinstance(vuln, dict) and vuln.get("severity") == "high"
            ),
            "medium_vulns": sum(
                1 for vuln in vulnerabilities if isinstance(vuln, dict) and vuln.get("severity") == "medium"
            ),
            "low_vulns": sum(
                1 for vuln in vulnerabilities if isinstance(vuln, dict) and vuln.get("severity") == "low"
            ),
            "risk_level": self._infer_risk_level(dependency_results),
            "risk_score": (
                risk_scores[0]["risk_score"]
                if risk_scores and isinstance(risk_scores[0], dict) and "risk_score" in risk_scores[0]
                else "N/A"
            ),
            "findings": dependency_results,
        }

    def _build_step_parameters(
        self,
        step: PlanStep,
        task: TaskRequest,
        results: dict[int, TaskResult],
    ) -> dict[str, Any]:
        """Merge the original step parameters with dependency context."""
        parameters = dict(step.parameters)
        dependency_results = self._collect_dependency_results(step, results)
        dependency_payloads = [
            dependency["result"]
            for dependency in dependency_results
            if isinstance(dependency.get("result"), dict)
        ]

        parameters.setdefault("trace_id", task.task_id)
        parameters.setdefault("tenant_id", task.context.get("tenant_id", "default"))
        parameters.setdefault("task_id", task.task_id)
        parameters.setdefault("task_type", task.task_type)
        parameters.setdefault("task_description", task.description)
        parameters.setdefault("step_id", step.step_id)
        parameters.setdefault("agent_role", step.agent_role.value)
        parameters["dependency_results"] = dependency_results
        parameters["dependency_summary"] = self._compose_dependency_summary(dependency_results)

        if "content" not in parameters:
            content = task.parameters.get("content")
            if content:
                parameters["content"] = content
            else:
                for payload in dependency_payloads:
                    for key in ("content", "log_content", "content_excerpt"):
                        if payload.get(key):
                            parameters["content"] = payload[key]
                            break
                    if "content" in parameters:
                        break

        if "iocs" not in parameters:
            iocs = self._collect_nested_values(dependency_payloads, ("iocs",))
            if iocs:
                parameters["iocs"] = iocs

        if "vulnerabilities" not in parameters:
            vulnerabilities = self._collect_nested_values(
                dependency_payloads, ("vulnerabilities", "findings")
            )
            if vulnerabilities:
                parameters["vulnerabilities"] = vulnerabilities

        if "open_ports" not in parameters and "ports" not in parameters:
            ports = self._collect_nested_values(dependency_payloads, ("open_ports", "ports"))
            if ports:
                parameters["open_ports"] = ports

        if "services" not in parameters:
            for payload in dependency_payloads:
                services = payload.get("services")
                if isinstance(services, dict) and services:
                    parameters["services"] = services
                    break

        if step.action.startswith("generate_") or step.agent_role == AgentRole.RESPONDER:
            parameters.setdefault(
                "data",
                {
                    "task_type": task.task_type,
                    "description": task.description,
                    "dependency_summary": self._compose_dependency_summary(dependency_results),
                    "step_results": dependency_results,
                },
            )

        if step.action in {"generate_report", "generate_incident_report"}:
            parameters.setdefault(
                "incident",
                {
                    "task_type": task.task_type,
                    "description": task.description,
                    "iocs": parameters.get("iocs", []),
                    "findings": self._collect_nested_values(
                        dependency_payloads, ("patterns", "anomalies", "correlations")
                    ),
                    "actions_taken": [
                        dependency.get("result")
                        for dependency in dependency_results
                        if dependency.get("result")
                    ],
                },
            )
            parameters.setdefault(
                "timeline",
                [
                    {
                        "step_id": dependency["step_id"],
                        "agent_id": dependency["agent_id"],
                        "success": dependency["success"],
                    }
                    for dependency in dependency_results
                ],
            )

        if step.action == "generate_hunting_report":
            parameters.setdefault("hypothesis", task.description)
            parameters.setdefault(
                "findings",
                self._collect_nested_values(
                    dependency_payloads, ("patterns", "anomalies", "correlations")
                ),
            )
            parameters.setdefault(
                "validated_findings",
                self._collect_nested_values(dependency_payloads, ("validated_findings",)),
            )
            parameters.setdefault(
                "analysis",
                {
                    "dependency_summary": self._compose_dependency_summary(dependency_results),
                    "iocs": parameters.get("iocs", []),
                },
            )

        if step.action == "generate_pentest_report":
            parameters.setdefault("target", task.parameters.get("target", ""))
            parameters.setdefault(
                "findings",
                self._collect_nested_values(dependency_payloads, ("vulnerabilities", "findings")),
            )
            parameters.setdefault(
                "attack_paths",
                self._collect_nested_values(dependency_payloads, ("attack_paths", "paths")),
            )

        if step.action == "generate_vuln_report":
            parameters.setdefault(
                "assessment",
                self._build_assessment_context(dependency_payloads, dependency_results),
            )

        return parameters

    async def _execute_plan(self, plan: ExecutionPlan) -> dict[int, TaskResult]:
        """Execute the plan while preserving dependency order."""
        results: dict[int, TaskResult] = {}
        completed_steps: set[int] = set()

        while len(completed_steps) < len(plan.steps):
            ready_steps = []
            for step in plan.steps:
                if step.step_id in completed_steps:
                    continue
                if all(dep in completed_steps for dep in step.depends_on):
                    ready_steps.append(step)

            if not ready_steps:
                logger.error("Deadlock detected in execution plan")
                break

            import asyncio
            tasks = []
            for step in ready_steps:
                tasks.append(self._execute_step(step, plan.task_request, results))

            step_results = await asyncio.gather(*tasks, return_exceptions=True)

            for step, result in zip(ready_steps, step_results):
                if isinstance(result, Exception):
                    logger.error("Step %d failed: %s", step.step_id, result)
                    results[step.step_id] = TaskResult(
                        task_id=plan.task_request.task_id,
                        success=False,
                        error=str(result),
                        agent_id="coordinator",
                    )
                else:
                    results[step.step_id] = result
                completed_steps.add(step.step_id)

        return results

    async def _execute_step(
        self,
        step: PlanStep,
        task: TaskRequest,
        results: dict[int, TaskResult],
    ) -> TaskResult:
        """Execute a single step with real agent invocation when possible."""
        import time

        start_time = time.time()
        step_parameters = self._build_step_parameters(step, task, results)

        if self.tools:
            tool_name = step.action
            tool = self.tools.get(tool_name)
            if tool:
                try:
                    from app.governance.tool_protocol import ToolInput

                    input_data = ToolInput(
                        trace_id=task.task_id,
                        tenant_id=task.context.get("tenant_id", "default"),
                        **step_parameters,
                    )
                    result = await tool.execute(input_data)
                    execution_time = int((time.time() - start_time) * 1000)
                    return TaskResult(
                        task_id=task.task_id,
                        success=result.success,
                        result=result.data,
                        error=result.error,
                        execution_time_ms=execution_time,
                        agent_id=self.agent_id,
                    )
                except Exception as e:
                    logger.error("Tool execution failed for %s: %s", tool_name, e)

        agent = agent_registry.get_available_by_role(step.agent_role)
        if not agent:
            return await self._execute_as_agent(step, task, step_parameters)

        agent_instance = message_bus.get_agent(agent.agent_id)
        if agent_instance is None:
            logger.warning(
                "Agent '%s' is registered in the registry but missing from the message bus",
                agent.agent_id,
            )
            return await self._execute_as_agent(step, task, step_parameters)

        task_request = TaskRequest(
            task_type=step.action,
            description=f"Execute {step.action} for task {task.task_id}",
            parameters=step_parameters,
            priority=task.priority,
            context={
                **task.context,
                "parent_task": task.task_id,
                "step_id": step.step_id,
                "agent_role": step.agent_role.value,
            },
        )

        previous_task = getattr(agent_instance, "_current_task", None)
        start_agent_time = time.time()
        agent_instance._current_task = task.task_id
        agent_instance.update_load(0.8)
        try:
            import asyncio
            result = await asyncio.wait_for(
                agent_instance.execute_task(task_request),
                timeout=120,  # 2-minute timeout per agent step
            )
            if result.execution_time_ms <= 0:
                result.execution_time_ms = int((time.time() - start_agent_time) * 1000)
            return result
        except asyncio.TimeoutError:
            from multi_agent.base_agent import TaskResult, TaskStatus
            return TaskResult(
                task_id=task.task_id,
                status=TaskStatus.FAILED,
                output={},
                execution_time_ms=int((time.time() - start_agent_time) * 1000),
                error="Agent step timed out after 120s",
            )
        finally:
            agent_instance._current_task = previous_task
            agent_instance.update_load(0.0)

    async def _execute_as_agent(
        self,
        step: PlanStep,
        task: TaskRequest,
        step_parameters: dict[str, Any],
    ) -> TaskResult:
        """Execute a step without a dedicated agent instance."""
        if self.tools:
            tool_name = step.action
            tool = self.tools.get(tool_name)
            if tool:
                from app.governance.tool_protocol import ToolInput

                input_data = ToolInput(
                    trace_id=task.task_id,
                    tenant_id=task.context.get("tenant_id", "default"),
                    **step_parameters,
                )
                result = await tool.execute(input_data)
                return TaskResult(
                    task_id=task.task_id,
                    success=result.success,
                    result=result.data,
                    error=result.error,
                    agent_id=self.agent_id,
                )

        if step.optional:
            return TaskResult(
                task_id=task.task_id,
                success=True,
                result={
                    "step_id": step.step_id,
                    "action": step.action,
                    "status": "skipped",
                    "reason": "Optional step could not be executed by a registered agent or tool",
                },
                agent_id=self.agent_id,
            )

        return TaskResult(
            task_id=task.task_id,
            success=False,
            error=(
                f"No registered agent available for role '{step.agent_role.value}' "
                f"and no tool mapped to '{step.action}'"
            ),
            agent_id=self.agent_id,
        )

    async def _aggregate_results(
        self, task: TaskRequest, results: dict[int, TaskResult]
    ) -> dict[str, Any]:
        """Aggregate the results from all executed steps."""
        successful = [r for r in results.values() if r.success]
        failed = [r for r in results.values() if not r.success]

        aggregated = {
            "task_type": task.task_type,
            "description": task.description,
            "total_steps": len(results),
            "successful_steps": len(successful),
            "failed_steps": len(failed),
            "step_results": {
                step_id: {
                    "success": r.success,
                    "result": r.result,
                    "error": r.error,
                    "agent": r.agent_id,
                    "time_ms": r.execution_time_ms,
                }
                for step_id, r in results.items()
            },
        }

        if failed:
            aggregated["summary"] = f"任务完成 {len(successful)}/{len(results)} 步成功"
            aggregated["status"] = "partial"
        else:
            aggregated["summary"] = f"任务完成 共 {len(results)} 步全部成功"
            aggregated["status"] = "completed"

        return aggregated

    async def handle_query(self, query: dict[str, Any]) -> dict[str, Any]:
        """处理查询请求"""
        query_type = query.get("type", "")

        if query_type == "status":
            return self._get_system_status()
        elif query_type == "agents":
            return {"agents": agent_registry.list_all()}
        elif query_type == "capabilities":
            return {"capabilities": self._get_available_capabilities()}

        return {"error": f"Unknown query type: {query_type}"}

    def _get_system_status(self) -> dict[str, Any]:
        """获取系统状态"""
        return {
            "coordinator": self.agent_id,
            "agent_stats": agent_registry.get_stats(),
            "pending_tasks": len(self._pending_tasks),
            "completed_tasks": len(self._task_results),
        }

    def _get_available_capabilities(self) -> list[str]:
        """获取系统可用能力"""
        capabilities = set()
        for agent in agent_registry.list_all():
            capabilities.update(agent.capabilities)
        return sorted(capabilities)
