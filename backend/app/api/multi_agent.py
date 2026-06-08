"""Multi-Agent API endpoints.

提供多智能体协同的API接口。
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.deps import get_current_user
from app.multi_agent.coordinator import Coordinator
from app.multi_agent.protocol import AgentRole, TaskPriority, TaskRequest
from app.multi_agent.registry import agent_registry

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/multi-agent", tags=["multi-agent"])

# 全局协调者实例
_coordinator: Optional[Coordinator] = None


def get_coordinator() -> Coordinator:
    """获取或创建协调者实例"""
    global _coordinator
    if _coordinator is None:
        # 导入真实的 tool_registry 和 llm_router
        from app.agent.tool_executor import tool_registry
        from app.llm.router import router as llm_router

        _coordinator = Coordinator(
            agent_id="coordinator",
            llm_router=llm_router,
            tool_registry=tool_registry,
        )

        # 注册子 Agent
        from app.multi_agent.analyzer_agent import AnalyzerAgent
        from app.multi_agent.executor_agent import ExecutorAgent
        from app.multi_agent.responder_agent import ResponderAgent
        from app.multi_agent.planner_agent import PlannerAgent
        from app.multi_agent.base_agent import message_bus

        # 创建并注册子 Agent
        analyzer = AnalyzerAgent(
            agent_id="analyzer",
            llm_router=llm_router,
            tool_registry=tool_registry,
        )
        executor = ExecutorAgent(
            agent_id="executor",
            llm_router=llm_router,
            tool_registry=tool_registry,
        )
        responder = ResponderAgent(
            agent_id="responder",
            llm_router=llm_router,
            tool_registry=tool_registry,
        )
        planner = PlannerAgent(
            agent_id="planner",
            llm_router=llm_router,
            tool_registry=tool_registry,
        )

        # 注册到消息总线
        message_bus.register_agent(_coordinator)
        message_bus.register_agent(analyzer)
        message_bus.register_agent(executor)
        message_bus.register_agent(responder)
        message_bus.register_agent(planner)

        logger.info("Multi-agent system initialized with tool_registry and llm_router")

    return _coordinator


class TaskRequestModel(BaseModel):
    """任务请求模型"""
    task_type: str = Field(..., description="任务类型")
    description: str = Field(..., description="任务描述")
    parameters: dict[str, Any] = Field(default_factory=dict, description="任务参数")
    priority: str = Field(default="medium", description="优先级: critical/high/medium/low")
    deadline_seconds: Optional[int] = Field(default=None, description="截止时间（秒）")


class TaskResponseModel(BaseModel):
    """任务响应模型"""
    task_id: str
    success: bool
    result: dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    execution_time_ms: int = 0


@router.post("/tasks", response_model=TaskResponseModel)
async def create_task(
    request: TaskRequestModel,
    user=Depends(get_current_user),
):
    """创建多智能体任务"""
    coordinator = get_coordinator()

    # 转换优先级
    priority_map = {
        "critical": TaskPriority.CRITICAL,
        "high": TaskPriority.HIGH,
        "medium": TaskPriority.MEDIUM,
        "low": TaskPriority.LOW,
    }
    priority = priority_map.get(request.priority.lower(), TaskPriority.MEDIUM)

    # 创建任务请求
    task = TaskRequest(
        task_type=request.task_type,
        description=request.description,
        parameters=request.parameters,
        priority=priority,
        deadline_seconds=request.deadline_seconds,
        context={"user_id": user.get("id", ""), "tenant_id": user.get("tenant_id", "default")},
    )

    # 执行任务
    result = await coordinator.execute_task(task)

    return TaskResponseModel(
        task_id=result.task_id,
        success=result.success,
        result=result.result,
        error=result.error,
        execution_time_ms=result.execution_time_ms,
    )


@router.get("/agents")
async def list_agents(user=Depends(get_current_user)):
    """列出所有注册的Agent"""
    agents = agent_registry.list_all()
    return {
        "agents": [
            {
                "agent_id": a.agent_id,
                "role": a.role.value,
                "status": a.status,
                "capabilities": a.capabilities,
                "load": a.load,
            }
            for a in agents
        ],
        "stats": agent_registry.get_stats(),
    }


@router.get("/agents/{role}")
async def list_agents_by_role(role: str, user=Depends(get_current_user)):
    """按角色列出Agent"""
    try:
        agent_role = AgentRole(role)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid role: {role}")

    agents = agent_registry.get_by_role(agent_role)
    return {
        "role": role,
        "agents": [
            {
                "agent_id": a.agent_id,
                "status": a.status,
                "capabilities": a.capabilities,
                "load": a.load,
            }
            for a in agents
        ],
    }


@router.get("/capabilities")
async def list_capabilities(user=Depends(get_current_user)):
    """列出系统可用能力"""
    capabilities = set()
    for agent in agent_registry.list_all():
        capabilities.update(agent.capabilities)

    return {
        "capabilities": sorted(capabilities),
        "agent_count": len(agent_registry.list_all()),
    }


@router.get("/status")
async def get_system_status(user=Depends(get_current_user)):
    """获取多智能体系统状态"""
    return {
        "status": "running",
        "agent_stats": agent_registry.get_stats(),
        "agents": [
            {
                "agent_id": a.agent_id,
                "role": a.role.value,
                "status": a.status,
                "capabilities": a.capabilities or [],
                "load": a.load or 0.0,
            }
            for a in agent_registry.list_all()
        ],
    }


@router.post("/tasks/incident-response")
async def create_incident_response_task(
    request: TaskRequestModel,
    user=Depends(get_current_user),
):
    """创建应急响应任务（快捷接口）"""
    request.task_type = "incident_response"
    return await create_task(request, user)


@router.post("/tasks/penetration-test")
async def create_pentest_task(
    request: TaskRequestModel,
    user=Depends(get_current_user),
):
    """创建渗透测试任务（快捷接口）"""
    request.task_type = "penetration_test"
    return await create_task(request, user)


@router.post("/tasks/threat-hunting")
async def create_threat_hunting_task(
    request: TaskRequestModel,
    user=Depends(get_current_user),
):
    """创建威胁狩猎任务（快捷接口）"""
    request.task_type = "threat_hunting"
    return await create_task(request, user)


@router.post("/tasks/vulnerability-assessment")
async def create_vuln_assessment_task(
    request: TaskRequestModel,
    user=Depends(get_current_user),
):
    """创建漏洞评估任务（快捷接口）"""
    request.task_type = "vulnerability_assessment"
    return await create_task(request, user)
