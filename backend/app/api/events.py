"""Events API — 事件驱动管线API端点。

提供告警管线的状态查询和管理功能。
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.deps import get_current_user
from app.events.alert_pipeline import get_alert_pipeline

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/events", tags=["Events"])


class AlertData(BaseModel):
    """告警数据"""
    id: Optional[str] = None
    rule_id: str = Field(..., description="规则ID")
    description: str = Field(default="", description="告警描述")
    src_ip: Optional[str] = Field(default=None, description="源IP")
    dst_ip: Optional[str] = Field(default=None, description="目标IP")
    severity: str = Field(default="medium", description="严重等级")
    verdict: Optional[str] = Field(default=None, description="判定结果")
    confidence: float = Field(default=0.0, description="置信度")


@router.get("/pipeline/stats")
async def get_pipeline_stats(user=Depends(get_current_user)):
    """获取告警管线统计信息"""
    try:
        pipeline = get_alert_pipeline()
        stats = pipeline.get_stats()
        return stats
    except Exception as e:
        logger.error("Failed to get pipeline stats: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/pipeline/enable")
async def enable_pipeline(user=Depends(get_current_user)):
    """启用告警管线"""
    try:
        pipeline = get_alert_pipeline()
        pipeline.enable()
        return {"status": "enabled"}
    except Exception as e:
        logger.error("Failed to enable pipeline: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/pipeline/disable")
async def disable_pipeline(user=Depends(get_current_user)):
    """禁用告警管线"""
    try:
        pipeline = get_alert_pipeline()
        pipeline.disable()
        return {"status": "disabled"}
    except Exception as e:
        logger.error("Failed to disable pipeline: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/pipeline/test")
async def test_pipeline(
    alert: AlertData,
    user=Depends(get_current_user),
):
    """测试告警管线"""
    try:
        pipeline = get_alert_pipeline()
        result = await pipeline.process_alert(alert.model_dump())
        return result
    except Exception as e:
        logger.error("Failed to test pipeline: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/pipeline/connections")
async def get_pipeline_connections(user=Depends(get_current_user)):
    """获取管线连接状态"""
    try:
        from app.rules.rule_manager import get_rule_manager
        from app.knowledge_graph.graph import get_knowledge_graph
        from app.response.action_manager import get_action_manager
        from app.multi_agent.registry import agent_registry

        rule_manager = get_rule_manager()
        knowledge_graph = get_knowledge_graph()
        action_manager = get_action_manager()

        return {
            "connections": {
                "rule_engine": {
                    "status": "connected",
                    "stats": rule_manager.get_stats(),
                },
                "knowledge_graph": {
                    "status": "connected",
                    "stats": knowledge_graph.get_stats(),
                },
                "response_actions": {
                    "status": "connected",
                    "stats": action_manager.get_stats(),
                },
                "multi_agent": {
                    "status": "connected",
                    "stats": agent_registry.get_stats(),
                },
            },
            "overall_status": "healthy",
        }
    except Exception as e:
        logger.error("Failed to get pipeline connections: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
