"""Response Actions API — 响应动作API端点。

提供响应动作的执行、查询和管理功能。
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.deps import get_current_user
from app.response.action_manager import get_action_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/response-actions", tags=["Response Actions"])


class ExecuteActionRequest(BaseModel):
    """执行动作请求"""
    action_type: str = Field(..., description="动作类型")
    params: dict[str, Any] = Field(default_factory=dict, description="动作参数")


class AutoRespondRequest(BaseModel):
    """自动响应请求"""
    threat_data: dict[str, Any] = Field(..., description="威胁数据")


@router.get("/stats")
async def get_action_stats(user=Depends(get_current_user)):
    """获取动作统计信息（内存 + 数据库）"""
    try:
        manager = get_action_manager()
        stats = manager.get_stats()

        # 如果内存统计为空，从数据库加载
        if stats.get("total_executions", 0) == 0:
            try:
                from app.models.base import get_session_factory
                from app.models.models import ResponseAction
                from sqlalchemy import select, func

                factory = get_session_factory()
                if factory:
                    async with factory() as session:
                        total = await session.scalar(select(func.count(ResponseAction.id)))
                        if total and total > 0:
                            successful = await session.scalar(
                                select(func.count(ResponseAction.id)).where(ResponseAction.success == True)
                            )
                            stats = {
                                "total_executions": total,
                                "successful": successful or 0,
                                "failed": total - (successful or 0),
                                "success_rate": round((successful or 0) / total, 4) if total else 0,
                                "by_type": {},
                                "pending_rollbacks": 0,
                            }
            except Exception as e:
                logger.debug("Could not load stats from DB: %s", e)

        return stats
    except Exception as e:
        logger.error("Failed to get action stats: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history")
async def get_action_history(
    limit: int = 100,
    user=Depends(get_current_user),
):
    """获取动作执行历史（内存 + 数据库）"""
    try:
        manager = get_action_manager()
        history = manager.get_action_history(limit)

        # 如果内存历史为空，从数据库加载
        if not history:
            try:
                from app.models.base import get_session_factory
                from app.models.models import ResponseAction
                from sqlalchemy import select

                factory = get_session_factory()
                if factory:
                    async with factory() as session:
                        query = (
                            select(ResponseAction)
                            .order_by(ResponseAction.created_at.desc())
                            .limit(limit)
                        )
                        result = await session.execute(query)
                        records = result.scalars().all()
                        history = [
                            {
                                "action_id": r.id,
                                "action_type": r.action_type,
                                "status": r.status,
                                "success": r.success,
                                "message": r.message,
                                "details": r.details,
                                "params": r.params,
                                "executed_at": r.created_at.isoformat() if r.created_at else None,
                                "rollback_available": r.rollback_available,
                            }
                            for r in records
                        ]
            except Exception as e:
                logger.debug("Could not load history from DB: %s", e)

        return {"history": history, "total": len(history)}
    except Exception as e:
        logger.error("Failed to get action history: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/types")
async def get_action_types(user=Depends(get_current_user)):
    """获取可用动作类型"""
    try:
        manager = get_action_manager()
        types = manager.get_available_actions()
        return {"types": types}
    except Exception as e:
        logger.error("Failed to get action types: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/execute")
async def execute_action(
    request: ExecuteActionRequest,
    user=Depends(get_current_user),
):
    """执行响应动作"""
    try:
        manager = get_action_manager()
        result = await manager.execute_action(request.action_type, request.params)

        return {
            "success": result.success,
            "action_id": result.action_id,
            "action_type": result.action_type,
            "status": result.status.value,
            "message": result.message,
            "details": result.details,
            "rollback_available": result.rollback_available,
        }

    except Exception as e:
        logger.error("Failed to execute action: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/auto-respond")
async def auto_respond(
    request: AutoRespondRequest,
    user=Depends(get_current_user),
):
    """自动响应"""
    try:
        manager = get_action_manager()
        results = await manager.auto_respond(request.threat_data)

        successful = sum(1 for r in results if r.success)
        failed = len(results) - successful

        return {
            "success": failed == 0,
            "total_actions": len(results),
            "successful": successful,
            "failed": failed,
            "results": [
                {
                    "action_id": r.action_id,
                    "action_type": r.action_type,
                    "status": r.status.value,
                    "success": r.success,
                    "message": r.message,
                }
                for r in results
            ],
        }

    except Exception as e:
        logger.error("Failed to auto respond: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rollback/{action_id}")
async def rollback_action(
    action_id: str,
    user=Depends(get_current_user),
):
    """回滚动作"""
    try:
        manager = get_action_manager()
        result = await manager.rollback_action(action_id)

        return {
            "success": result.success,
            "action_id": result.action_id,
            "action_type": result.action_type,
            "status": result.status.value,
            "message": result.message,
        }

    except Exception as e:
        logger.error("Failed to rollback action: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
