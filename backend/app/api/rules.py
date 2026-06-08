"""Rules Engine API — 规则引擎API端点。

提供Sigma/YARA规则的查询、匹配和管理功能。
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.deps import get_current_user
from app.rules.rule_manager import get_rule_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/rules", tags=["Rules Engine"])


class RuleMatchRequest(BaseModel):
    """规则匹配请求"""
    match_type: str = Field(..., description="匹配类型: log, file, data")
    content: Optional[str] = Field(default=None, description="日志内容或数据")
    file_path: Optional[str] = Field(default=None, description="文件路径")
    logsource: Optional[dict[str, str]] = Field(default=None, description="日志源信息")
    rule_type: Optional[str] = Field(default=None, description="规则类型: sigma, yara, all")


@router.get("/stats")
async def get_rule_stats(user=Depends(get_current_user)):
    """获取规则统计信息"""
    try:
        manager = get_rule_manager()
        stats = manager.get_stats()
        return stats
    except Exception as e:
        logger.error("Failed to get rule stats: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/list")
async def list_rules(
    rule_type: Optional[str] = None,
    user=Depends(get_current_user),
):
    """列出规则"""
    try:
        manager = get_rule_manager()
        rules = manager.list_rules(rule_type)
        return rules
    except Exception as e:
        logger.error("Failed to list rules: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/match")
async def match_rules(
    request: RuleMatchRequest,
    user=Depends(get_current_user),
):
    """执行规则匹配"""
    try:
        manager = get_rule_manager()
        matches = []

        if request.match_type == "log":
            if not request.content:
                raise HTTPException(status_code=400, detail="content is required for log matching")

            import json
            try:
                events = json.loads(request.content)
                if not isinstance(events, list):
                    events = [events]
            except json.JSONDecodeError:
                events = [{"raw": line} for line in request.content.split("\n") if line.strip()]

            matches = manager.match_log_events(events, request.logsource)

        elif request.match_type == "file":
            if not request.file_path:
                raise HTTPException(status_code=400, detail="file_path is required for file matching")
            matches = manager.match_file(request.file_path)

        elif request.match_type == "data":
            if not request.content:
                raise HTTPException(status_code=400, detail="content is required for data matching")

            import base64
            try:
                data = base64.b64decode(request.content)
            except Exception:
                data = request.content.encode("utf-8")

            matches = manager.match_data(data)

        else:
            raise HTTPException(status_code=400, detail=f"Invalid match_type: {request.match_type}")

        # 过滤规则类型
        if request.rule_type and request.rule_type != "all":
            matches = [m for m in matches if m.rule_type == request.rule_type]

        # 转换结果
        results = [
            {
                "rule_type": m.rule_type,
                "rule_name": m.rule_name,
                "rule_id": m.rule_id,
                "description": m.description,
                "severity": m.severity,
                "confidence": m.confidence,
                "matched_conditions": m.matched_conditions,
                "recommendations": m.recommendations,
            }
            for m in matches
        ]

        # 生成摘要
        critical = sum(1 for m in matches if m.severity == "critical")
        high = sum(1 for m in matches if m.severity == "high")
        medium = sum(1 for m in matches if m.severity == "medium")
        low = sum(1 for m in matches if m.severity == "low")

        summary = f"检测到{len(matches)}个威胁"
        if critical:
            summary += f": {critical}个关键"
        if high:
            summary += f" {high}个高危"
        if medium:
            summary += f" {medium}个中危"
        if low:
            summary += f" {low}个低危"

        return {
            "success": True,
            "total_matches": len(matches),
            "matches": results,
            "summary": summary,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Rule matching failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sigma/rules")
async def list_sigma_rules(user=Depends(get_current_user)):
    """列出Sigma规则"""
    try:
        manager = get_rule_manager()
        rules = manager.sigma_engine.list_rules()
        return {"rules": rules, "total": len(rules)}
    except Exception as e:
        logger.error("Failed to list sigma rules: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/yara/rules")
async def list_yara_rules(user=Depends(get_current_user)):
    """列出YARA规则"""
    try:
        manager = get_rule_manager()
        rules = manager.yara_engine.list_rules()
        return {"rules": rules, "total": len(rules)}
    except Exception as e:
        logger.error("Failed to list yara rules: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
