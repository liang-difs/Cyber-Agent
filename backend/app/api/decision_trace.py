"""
Decision Trace API — 决策追踪 API。

提供决策追踪查询、回放和审计报告导出功能。
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from fastapi import APIRouter, HTTPException, Query, Depends
from fastapi.responses import JSONResponse, PlainTextResponse

from app.agent.decision_trace import decision_tracker
from app.api.deps import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/decision-trace", tags=["Decision Trace"])


@router.get("/{trace_id}")
async def get_decision_trace(
    trace_id: str,
    current_user: dict = Depends(get_current_user),
):
    """获取决策追踪记录"""
    trace = decision_tracker.get_trace(trace_id)
    if not trace:
        raise HTTPException(status_code=404, detail="决策追踪记录不存在")

    # Check tenant access
    if trace.tenant_id != current_user.get("tenant_id") and current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="无权访问此决策追踪记录")

    return {
        "trace_id": trace.trace_id,
        "session_id": trace.session_id,
        "user_id": trace.user_id,
        "tenant_id": trace.tenant_id,
        "query": trace.query,
        "start_time": trace.start_time,
        "end_time": trace.end_time,
        "total_duration_ms": trace.total_duration_ms,
        "success": trace.success,
        "error": trace.error,
        "final_answer": trace.final_answer,
        "final_confidence": trace.final_confidence,
        "total_steps": len(trace.steps),
    }


@router.get("/{trace_id}/chain")
async def get_decision_chain(
    trace_id: str,
    current_user: dict = Depends(get_current_user),
):
    """获取决策链（用于回放）"""
    trace = decision_tracker.get_trace(trace_id)
    if not trace:
        raise HTTPException(status_code=404, detail="决策追踪记录不存在")

    # Check tenant access
    if trace.tenant_id != current_user.get("tenant_id") and current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="无权访问此决策追踪记录")

    chain = decision_tracker.get_decision_chain(trace_id)
    return {"trace_id": trace_id, "chain": chain}


@router.get("/{trace_id}/evidence")
async def get_evidence_summary(
    trace_id: str,
    current_user: dict = Depends(get_current_user),
):
    """获取证据摘要"""
    trace = decision_tracker.get_trace(trace_id)
    if not trace:
        raise HTTPException(status_code=404, detail="决策追踪记录不存在")

    # Check tenant access
    if trace.tenant_id != current_user.get("tenant_id") and current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="无权访问此决策追踪记录")

    evidence = decision_tracker.get_evidence_summary(trace_id)
    return {"trace_id": trace_id, "evidence": evidence}


@router.get("/{trace_id}/export")
async def export_audit_report(
    trace_id: str,
    format: str = Query("json", enum=["json", "markdown"]),
    current_user: dict = Depends(get_current_user),
):
    """导出审计报告"""
    trace = decision_tracker.get_trace(trace_id)
    if not trace:
        raise HTTPException(status_code=404, detail="决策追踪记录不存在")

    # Check tenant access
    if trace.tenant_id != current_user.get("tenant_id") and current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="无权访问此决策追踪记录")

    report = decision_tracker.export_audit_report(trace_id, fmt=format)
    if not report:
        raise HTTPException(status_code=500, detail="导出审计报告失败")

    if format == "json":
        return JSONResponse(content={"trace_id": trace_id, "report": report})
    else:
        return PlainTextResponse(content=report, media_type="text/markdown")


@router.get("/{trace_id}/steps")
async def get_decision_steps(
    trace_id: str,
    current_user: dict = Depends(get_current_user),
):
    """获取决策步骤详情"""
    trace = decision_tracker.get_trace(trace_id)
    if not trace:
        raise HTTPException(status_code=404, detail="决策追踪记录不存在")

    # Check tenant access
    if trace.tenant_id != current_user.get("tenant_id") and current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="无权访问此决策追踪记录")

    steps = []
    for step in trace.steps:
        step_data = {
            "step_id": step.step_id,
            "turn": step.turn,
            "type": step.decision_type.value,
            "content": step.content,
            "timestamp": step.timestamp,
            "duration_ms": step.duration_ms,
            "confidence": step.confidence,
            "metadata": step.metadata,
            "evidence": [
                {
                    "source": e.source,
                    "source_type": e.source_type,
                    "content": e.content,
                    "confidence": e.confidence,
                    "tool_name": e.tool_name,
                }
                for e in step.evidence
            ],
        }
        steps.append(step_data)

    return {"trace_id": trace_id, "steps": steps}
