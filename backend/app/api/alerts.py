"""Alerts API — list and manage alerts."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.api.deps import get_current_user, scoped_tenant
from app.analysis.alert_assessment import build_alert_assessment
from app.rbac.permissions import Permission, require_permission

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


def _get_current_user(user: dict = Depends(get_current_user)) -> dict:
    return user


def _serialize_alert_record(alert, asset_map: dict | None = None) -> dict:
    """Serialize an Alert ORM row into the API shape."""
    ttp_ids = alert.ttp_ids or []
    assessment_ttps = [
        {"name": t, "tactic": "", "technique": t}
        for t in ttp_ids
        if isinstance(t, str)
    ]
    # Look up associated asset by src_ip
    asset_info = None
    if asset_map and alert.src_ip:
        asset_info = asset_map.get(alert.src_ip)
    return {
        "id": alert.id,
        "rule_id": alert.rule_id,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "severity": alert.severity,
        "status": alert.status,
        "verdict": alert.verdict,
        "confidence": alert.confidence,
        "asset": asset_info,
        "description": alert.description,
        "ttp_ids": alert.ttp_ids,
        "tenant_id": alert.tenant_id,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
        "updated_at": alert.updated_at.isoformat() if alert.updated_at else None,
        "assessment": build_alert_assessment(
            rule_id=alert.rule_id,
            description=alert.description or "",
            src_ip=alert.src_ip,
            dst_ip=alert.dst_ip,
            severity=alert.severity,
            status=alert.status,
            verdict=alert.verdict,
            confidence=alert.confidence if alert.confidence is not None else 0.0,
            ttps=assessment_ttps,
            evidence=[
                f"rule_id:{alert.rule_id}",
                *( [f"src_ip:{alert.src_ip}"] if alert.src_ip else [] ),
                *( [f"dst_ip:{alert.dst_ip}"] if alert.dst_ip else [] ),
            ],
        ),
    }


@router.get("")
async def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    src_ip: Optional[str] = None,
    limit: int = Query(default=50, le=500),
    offset: int = 0,
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.ALERT_VIEW, auth=Depends(_get_current_user))),
):
    """List alerts with optional filtering."""
    try:
        from app.models.base import get_session_factory
        from app.models.models import Alert
        from sqlalchemy import select, func

        factory = get_session_factory()
        if factory is None:
            return {"alerts": [], "total": 0, "warning": "Database not available"}

        async with factory() as session:
            tenant_id = scoped_tenant(user)
            query = select(Alert).where(Alert.tenant_id == tenant_id)
            count_query = select(func.count(Alert.id)).where(Alert.tenant_id == tenant_id)

            if severity:
                query = query.where(Alert.severity == severity)
                count_query = count_query.where(Alert.severity == severity)
            if status:
                query = query.where(Alert.status == status)
                count_query = count_query.where(Alert.status == status)
            if src_ip:
                query = query.where(Alert.src_ip == src_ip)
                count_query = count_query.where(Alert.src_ip == src_ip)

            total_result = await session.execute(count_query)
            total = total_result.scalar() or 0

            query = query.order_by(Alert.created_at.desc()).offset(offset).limit(limit)
            result = await session.execute(query)
            alerts = result.scalars().all()

        # Build asset map for src_ips
        asset_map = {}
        try:
            from app.models.models import Asset
            src_ips = list({a.src_ip for a in alerts if a.src_ip})
            if src_ips:
                async with factory() as session:
                    asset_q = select(Asset).where(
                        Asset.tenant_id == tenant_id,
                        Asset.ip_address.in_(src_ips),
                    )
                    asset_rows = (await session.execute(asset_q)).scalars().all()
                    for asset in asset_rows:
                        if asset.ip_address:
                            asset_map[asset.ip_address] = {
                                "name": asset.name,
                                "asset_type": asset.asset_type,
                                "criticality": asset.criticality,
                                "owner": asset.owner,
                                "department": asset.department,
                            }
        except Exception:
            pass

        return {
            "alerts": [_serialize_alert_record(a, asset_map) for a in alerts],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class AlertReviewRequest(BaseModel):
    status: str  # confirmed, false_positive, closed
    verdict: Optional[str] = None  # true_positive, false_positive, benign


@router.patch("/{alert_id}")
async def review_alert(
    alert_id: str,
    req: AlertReviewRequest,
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.ALERT_TRIAGE, auth=Depends(_get_current_user))),
):
    """Update alert status — analyst review action."""
    if req.status not in ("confirmed", "false_positive", "closed", "open"):
        raise HTTPException(status_code=400, detail=f"Invalid status: {req.status}")

    try:
        from app.models.base import get_session_factory
        from app.models.models import Alert
        from sqlalchemy import select
        from datetime import datetime, timezone

        factory = get_session_factory()
        if factory is None:
            raise HTTPException(status_code=503, detail="Database not available")

        async with factory() as session:
            tenant_id = scoped_tenant(user)
            result = await session.execute(
                select(Alert).where(Alert.id == alert_id, Alert.tenant_id == tenant_id)
            )
            alert = result.scalar_one_or_none()
            if not alert:
                raise HTTPException(status_code=404, detail="Alert not found")

            alert.status = req.status
            if req.verdict:
                alert.verdict = req.verdict
            alert.updated_at = datetime.now(timezone.utc)
            await session.commit()
            await session.refresh(alert)

        return _serialize_alert_record(alert)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class AlertAnalyzeRequest(BaseModel):
    task_type: str = "incident_response"


@router.post("/{alert_id}/analyze")
async def analyze_alert_with_multi_agent(
    alert_id: str,
    req: AlertAnalyzeRequest = AlertAnalyzeRequest(),
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.ALERT_TRIAGE, auth=Depends(_get_current_user))),
):
    """Launch multi-agent collaborative analysis for a specific alert.

    Creates an incident_response (or specified type) task with the alert's
    context injected into the task parameters.
    """
    try:
        from app.models.base import get_session_factory
        from app.models.models import Alert
        from sqlalchemy import select

        factory = get_session_factory()
        if factory is None:
            raise HTTPException(status_code=503, detail="Database not available")

        async with factory() as session:
            tenant_id = scoped_tenant(user)
            result = await session.execute(
                select(Alert).where(Alert.id == alert_id, Alert.tenant_id == tenant_id)
            )
            alert = result.scalar_one_or_none()
            if not alert:
                raise HTTPException(status_code=404, detail="Alert not found")

        # Build task parameters from alert context
        from app.api.multi_agent import get_coordinator
        from app.multi_agent.protocol import TaskRequest

        coordinator = get_coordinator()
        task = TaskRequest(
            task_type=req.task_type,
            description=f"Alert analysis: {alert.rule_id} from {alert.src_ip}",
            parameters={
                "alert_id": str(alert.id),
                "rule_id": alert.rule_id,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "severity": alert.severity,
                "description": alert.description or "",
                "ttp_ids": alert.ttp_ids or [],
            },
            context={"triggered_by": "alert_review", "alert_id": str(alert.id)},
        )

        result = await coordinator.execute_task(task)

        # Persist analysis results back to the Alert row
        try:
            from datetime import datetime, timezone
            result_dict = result.to_dict() if hasattr(result, "to_dict") else {}
            step_results = result_dict.get("step_results", {})

            # Extract verdict and confidence from step results
            extracted_verdict = None
            extracted_confidence = None
            extracted_ttps: list[str] = list(alert.ttp_ids or [])

            for _sid, step in step_results.items():
                step_output = step.get("result", {})
                if not isinstance(step_output, dict):
                    continue
                # Look for verdict/confidence in any step output
                if step_output.get("verdict") and not extracted_verdict:
                    extracted_verdict = step_output["verdict"]
                if step_output.get("confidence") is not None and extracted_confidence is None:
                    extracted_confidence = float(step_output["confidence"])
                # Collect TTPs from step outputs
                for ttp in step_output.get("ttp_ids", step_output.get("ttps", [])):
                    if isinstance(ttp, str) and ttp not in extracted_ttps:
                        extracted_ttps.append(ttp)
                    elif isinstance(ttp, dict):
                        tid = ttp.get("technique", "")
                        if tid and tid not in extracted_ttps:
                            extracted_ttps.append(tid)

            async with factory() as session:
                db_result = await session.execute(
                    select(Alert).where(Alert.id == alert_id)
                )
                db_alert = db_result.scalar_one_or_none()
                if db_alert:
                    if extracted_verdict:
                        db_alert.verdict = extracted_verdict
                    if extracted_confidence is not None:
                        db_alert.confidence = round(extracted_confidence, 2)
                    if extracted_ttps:
                        db_alert.ttp_ids = extracted_ttps
                    db_alert.status = "analyzed"
                    db_alert.updated_at = datetime.now(timezone.utc)
                    await session.commit()
        except Exception as persist_err:
            import logging
            logging.getLogger(__name__).warning("Failed to persist analysis result for alert %s: %s", alert_id, persist_err)

        return {
            "success": result.success if hasattr(result, "success") else True,
            "task_id": str(result.task_id) if hasattr(result, "task_id") else None,
            "alert_id": str(alert.id),
            "task_type": req.task_type,
            "result": result.to_dict() if hasattr(result, "to_dict") else str(result),
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
