"""Audit API — view audit logs."""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.deps import get_current_user, scoped_tenant
from app.rbac.permissions import Permission, require_permission

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


def _get_current_user(user: dict = Depends(get_current_user)) -> dict:
    return user


@router.get("/logs")
async def get_audit_logs(
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.AUDIT_VIEW, auth=Depends(_get_current_user))),
):
    """Get audit logs with optional filtering."""

    try:
        from app.models.base import get_session_factory
        from app.models.models import AuditLog
        from sqlalchemy import select, func

        factory = get_session_factory()
        if factory is None:
            return {"logs": [], "total": 0, "warning": "Database not available"}

        try:
            async with factory() as session:
                tenant_id = scoped_tenant(user)
                query = select(AuditLog).where(AuditLog.tenant_id == tenant_id)
                count_query = select(func.count(AuditLog.id)).where(AuditLog.tenant_id == tenant_id)

                if user_id:
                    query = query.where(AuditLog.user_id == user_id)
                    count_query = count_query.where(AuditLog.user_id == user_id)
                if action:
                    query = query.where(AuditLog.action == action)
                    count_query = count_query.where(AuditLog.action == action)

                total_result = await session.execute(count_query)
                total = total_result.scalar() or 0

                query = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit)
                result = await session.execute(query)
                logs = result.scalars().all()

            return {
                "logs": [
                    {
                        "id": log.id,
                        "user_id": log.user_id,
                        "action": log.action,
                        "resource": log.resource,
                        "detail": log.detail,
                        "ip_address": log.ip_address,
                        "tenant_id": log.tenant_id,
                        "created_at": log.created_at.isoformat() if log.created_at else None,
                    }
                    for log in logs
                ],
                "total": total,
                "limit": limit,
                "offset": offset,
            }
        except Exception as db_error:
            logger.warning("Database query failed: %s", db_error)
            return {"logs": [], "total": 0, "warning": "Database connection failed"}

    except Exception as e:
        logger.error("Audit log error: %s", e)
        return {"logs": [], "total": 0, "error": str(e)}
