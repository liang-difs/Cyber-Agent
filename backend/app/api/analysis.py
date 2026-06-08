"""Analysis API — attack chain tracing and correlation analysis."""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.api.deps import get_current_user, scoped_tenant
from app.rbac.permissions import Permission, require_permission

router = APIRouter(prefix="/api/v1/analysis", tags=["analysis"])


def _get_current_user(user: dict = Depends(get_current_user)) -> dict:
    return user


class AttackChainRequest(BaseModel):
    tenant_id: str = "default"
    time_window_hours: int = 24
    min_chain_length: int = 2
    src_ip: Optional[str] = None
    status: Optional[str] = None


class CorrelationRequest(BaseModel):
    tenant_id: str = "default"
    burst_window_minutes: int = 10
    burst_threshold: int = 5
    src_ip: Optional[str] = None


@router.post("/attack-chains")
async def get_attack_chains(
    req: AttackChainRequest,
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.ALERT_VIEW, auth=Depends(_get_current_user))),
):
    """Build attack chains from alerts in the database."""

    try:
        from app.models.base import get_session_factory
        from app.models.models import Alert
        from sqlalchemy import select

        factory = get_session_factory()
        if factory is None:
            # Fallback: no DB
            return {"chains": [], "total_alerts": 0, "warning": "Database not available"}

        async with factory() as session:
            tenant_id = scoped_tenant(user)
            query = select(Alert).where(Alert.tenant_id == tenant_id)
            if req.src_ip:
                query = query.where(Alert.src_ip == req.src_ip)
            if req.status:
                query = query.where(Alert.status == req.status)
            query = query.order_by(Alert.created_at).limit(1000)

            result = await session.execute(query)
            db_alerts = result.scalars().all()

        # Convert to dicts
        alerts = []
        for a in db_alerts:
            alerts.append({
                "id": a.id,
                "rule_id": a.rule_id,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "severity": a.severity,
                "description": a.description,
                "created_at": a.created_at,
                "status": a.status,
            })

        from app.analysis.attack_chain import build_attack_chains
        chains = build_attack_chains(
            alerts,
            time_window_hours=req.time_window_hours,
            min_chain_length=req.min_chain_length,
        )

        return {
            "chains": [c.to_dict() for c in chains],
            "total_alerts": len(alerts),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/correlate")
async def correlate_alerts(
    req: CorrelationRequest,
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.ALERT_VIEW, auth=Depends(_get_current_user))),
):
    """Run correlation analysis on alerts."""

    try:
        from app.models.base import get_session_factory
        from app.models.models import Alert
        from sqlalchemy import select

        factory = get_session_factory()
        if factory is None:
            return {"patterns": [], "total_alerts": 0, "warning": "Database not available"}

        async with factory() as session:
            tenant_id = scoped_tenant(user)
            query = select(Alert).where(Alert.tenant_id == tenant_id)
            if req.src_ip:
                query = query.where(Alert.src_ip == req.src_ip)
            query = query.order_by(Alert.created_at).limit(1000)

            result = await session.execute(query)
            db_alerts = result.scalars().all()

        alerts = []
        for a in db_alerts:
            alerts.append({
                "id": a.id,
                "rule_id": a.rule_id,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "severity": a.severity,
                "description": a.description,
                "created_at": a.created_at,
            })

        from app.analysis.correlation import analyze_correlations
        corr = analyze_correlations(
            alerts,
            burst_window_minutes=req.burst_window_minutes,
            burst_threshold=req.burst_threshold,
        )

        return corr.to_dict()

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
