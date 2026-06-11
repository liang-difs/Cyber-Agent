"""Dashboard API — aggregated stats for the homepage."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from app.api.deps import get_current_user, scoped_tenant
from app.core.config import get_settings
from app.rbac.permissions import Permission, require_permission

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


def _optional_service_status(service: str, *, production: bool) -> str:
    if production:
        return "error"
    if service == "celery":
        return "no_workers"
    return "unconfigured"


def _get_current_user(user: dict = Depends(get_current_user)) -> dict:
    return user


async def _get_alert_stats(tenant_id: str) -> dict:
    """Query alert stats from DB: total, by_severity, by_status, recent 5."""
    try:
        from app.models.base import get_session_factory
        from app.models.models import Alert
        from sqlalchemy import select, func

        factory = get_session_factory()
        if factory is None:
            return {"total": 0, "by_severity": {}, "by_status": {}, "recent": []}

        async with factory() as session:
            # Total count
            total_q = select(func.count(Alert.id)).where(Alert.tenant_id == tenant_id)
            total = (await session.execute(total_q)).scalar() or 0

            # By severity
            sev_q = (
                select(Alert.severity, func.count(Alert.id))
                .where(Alert.tenant_id == tenant_id)
                .group_by(Alert.severity)
            )
            by_severity = {row[0]: row[1] for row in (await session.execute(sev_q)).all()}

            # By status
            status_q = (
                select(Alert.status, func.count(Alert.id))
                .where(Alert.tenant_id == tenant_id)
                .group_by(Alert.status)
            )
            by_status = {row[0]: row[1] for row in (await session.execute(status_q)).all()}

            # Recent 5
            recent_q = (
                select(Alert)
                .where(Alert.tenant_id == tenant_id)
                .order_by(Alert.created_at.desc())
                .limit(5)
            )
            recent_rows = (await session.execute(recent_q)).scalars().all()
            recent = [
                {
                    "id": a.id,
                    "rule_id": a.rule_id,
                    "severity": a.severity,
                    "src_ip": a.src_ip,
                    "dst_ip": a.dst_ip,
                    "status": a.status,
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                }
                for a in recent_rows
            ]

        # Trend: alerts per day per severity (last 14 days)
        from sqlalchemy import func as sa_func, cast, Date
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=14)
        trend_q = (
            select(
                cast(Alert.created_at, Date).label("date"),
                Alert.severity,
                sa_func.count(Alert.id).label("count"),
            )
            .where(Alert.tenant_id == tenant_id)
            .where(Alert.created_at >= cutoff)
            .group_by(cast(Alert.created_at, Date), Alert.severity)
            .order_by(cast(Alert.created_at, Date))
        )
        trend_rows = (await session.execute(trend_q)).all()

        # Build {date: {critical: N, high: N, medium: N, low: N}} structure
        trend_map: dict[str, dict[str, int]] = {}
        for row in trend_rows:
            d = str(row[0])
            sev = row[1] or "medium"
            cnt = row[2]
            if d not in trend_map:
                trend_map[d] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            if sev in trend_map[d]:
                trend_map[d][sev] = cnt

        trend = [{"date": d, **counts} for d, counts in sorted(trend_map.items())]

        return {"total": total, "by_severity": by_severity, "by_status": by_status, "recent": recent, "trend": trend}
    except Exception:
        return {"total": 0, "by_severity": {}, "by_status": {}, "recent": [], "trend": []}


def _get_cve_stats() -> dict:
    """Get CVE stats from BM25 index."""
    try:
        from app.rag.bm25_search import bm25_instance

        stats = bm25_instance.stats()
        return {
            "total": stats.get("total", 0),
            "by_severity": stats.get("by_severity", {}),
            "recent": stats.get("recent", [])[:5],
        }
    except Exception:
        return {"total": 0, "by_severity": {}, "recent": []}


async def _get_health_summary() -> dict:
    """Get health summary for all services."""
    services = {}
    llm_model = None
    production = get_settings().app_env.lower() == "production"

    # PostgreSQL
    try:
        from app.models.base import get_session_factory
        from sqlalchemy import text

        factory = get_session_factory()
        if factory:
            async with factory() as session:
                await session.execute(text("SELECT 1"))
            services["postgresql"] = "ok"
        else:
            services["postgresql"] = "unconfigured"
    except Exception:
        services["postgresql"] = _optional_service_status("postgresql", production=production)

    # Redis
    try:
        import redis.asyncio as redis

        settings = get_settings()
        if settings.redis_url:
            r = redis.from_url(settings.redis_url)
            await r.ping()
            await r.aclose()
            services["redis"] = "ok"
        else:
            services["redis"] = "unconfigured"
    except Exception:
        services["redis"] = _optional_service_status("redis", production=production)

    # Elasticsearch
    try:
        import httpx

        settings = get_settings()
        if settings.elasticsearch_url:
            async with httpx.AsyncClient(timeout=3) as client:
                resp = await client.get(f"{settings.elasticsearch_url}/_cluster/health")
                if resp.status_code == 200:
                    services["elasticsearch"] = "ok"
                else:
                    services["elasticsearch"] = "error" if production else "unconfigured"
        else:
            services["elasticsearch"] = "unconfigured"
    except Exception:
        services["elasticsearch"] = _optional_service_status("elasticsearch", production=production)

    # Celery
    try:
        from app.tasks.celery_app import celery_app

        inspect = celery_app.control.inspect(timeout=1)
        active = inspect.active()
        services["celery"] = "ok" if active else "no_workers"
    except Exception:
        services["celery"] = _optional_service_status("celery", production=production)

    # LLM
    try:
        from app.llm.router import router as llm_router

        llm_status = llm_router.status()
        llm_model = llm_status.get("default_model")
        has_open = any(c.get("open") for c in llm_status.get("circuits", {}).values())
        services["llm"] = "degraded" if has_open else "ok"
    except Exception:
        services["llm"] = "error"

    overall = "healthy"
    if any(s in ("error", "degraded") for s in services.values()):
        overall = "degraded"

    return {"status": overall, "services": services, "llm_model": llm_model}


async def _get_session_count(tenant_id: str) -> int:
    """Count chat sessions for the tenant."""
    try:
        from app.models.base import get_session_factory
        from app.models.models import ChatSession
        from sqlalchemy import select, func

        factory = get_session_factory()
        if factory is None:
            return 0
        async with factory() as session:
            q = select(func.count(ChatSession.id)).where(ChatSession.tenant_id == tenant_id)
            return (await session.execute(q)).scalar() or 0
    except Exception:
        return 0


@router.get("")
async def get_dashboard(
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.ALERT_VIEW, auth=Depends(_get_current_user))),
):
    """Aggregated dashboard data: alerts, CVE, health, sessions."""
    import asyncio
    tenant_id = scoped_tenant(user)

    # _get_cve_stats is sync, wrap in to_thread for parallel execution
    alerts, cve_stats, health, session_count = await asyncio.gather(
        _get_alert_stats(tenant_id),
        asyncio.to_thread(_get_cve_stats),
        _get_health_summary(),
        _get_session_count(tenant_id),
    )

    return {
        "alerts": alerts,
        "cve": cve_stats,
        "health": health,
        "session_count": session_count,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
