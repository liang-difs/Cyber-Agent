"""Monitoring API - health checks and LLM routing controls."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.core.config import get_settings
from app.rbac.permissions import Permission, require_permission

router = APIRouter(tags=["monitoring"])
logger = logging.getLogger(__name__)


def _optional_service_failure(service: str, exc: Exception, *, production: bool) -> dict[str, str]:
    """Map optional infra failures to non-fatal dev statuses."""
    detail = str(exc)[:100]
    if production:
        return {"status": "error", "detail": detail}

    if service == "celery":
        return {
            "status": "no_workers",
            "detail": "Development mode: no Celery worker is running.",
        }

    labels = {
        "postgresql": "PostgreSQL",
        "redis": "Redis",
        "elasticsearch": "Elasticsearch",
    }
    return {
        "status": "unconfigured",
        "detail": f"Development mode: {labels.get(service, service)} is optional and not started.",
    }


@router.get("/health")
async def health_check():
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "0.5.0",
    }


@router.get("/health/detailed")
async def detailed_health():
    """Detailed health check with dependency status."""
    checks: dict[str, dict[str, object]] = {}
    settings = get_settings()
    production = settings.app_env.lower() == "production"

    # PostgreSQL
    try:
        from app.models.base import get_session_factory
        from sqlalchemy import text

        factory = get_session_factory()
        if factory:
            async with factory() as session:
                await session.execute(text("SELECT 1"))
            checks["postgresql"] = {"status": "ok"}
        else:
            checks["postgresql"] = {"status": "unconfigured"}
    except Exception as e:
        checks["postgresql"] = _optional_service_failure("postgresql", e, production=production)

    # Redis
    try:
        import redis.asyncio as redis

        if settings.redis_url:
            r = redis.from_url(settings.redis_url)
            await r.ping()
            await r.aclose()
            checks["redis"] = {"status": "ok"}
        else:
            checks["redis"] = {"status": "unconfigured"}
    except Exception as e:
        checks["redis"] = _optional_service_failure("redis", e, production=production)

    # Elasticsearch
    try:
        import httpx

        if settings.elasticsearch_url:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{settings.elasticsearch_url}/_cluster/health")
                if resp.status_code == 200:
                    data = resp.json()
                    checks["elasticsearch"] = {
                        "status": "ok",
                        "cluster_status": data.get("status"),
                    }
                else:
                    if production:
                        checks["elasticsearch"] = {"status": "error", "detail": f"HTTP {resp.status_code}"}
                    else:
                        checks["elasticsearch"] = {
                            "status": "unconfigured",
                            "detail": f"Development mode: Elasticsearch returned HTTP {resp.status_code}.",
                        }
        else:
            checks["elasticsearch"] = {"status": "unconfigured"}
    except Exception as e:
        checks["elasticsearch"] = _optional_service_failure("elasticsearch", e, production=production)

    # Celery
    try:
        from app.tasks.celery_app import celery_app

        inspect = celery_app.control.inspect(timeout=2)
        active = inspect.active()
        if active:
            checks["celery"] = {"status": "ok", "workers": len(active)}
        else:
            checks["celery"] = {"status": "no_workers"}
    except Exception as e:
        checks["celery"] = _optional_service_failure("celery", e, production=production)

    # LLM Router
    try:
        from app.llm.router import router as llm_router

        llm_status = llm_router.status()
        has_open_circuit = any(c.get("open") for c in llm_status.get("circuits", {}).values())
        checks["llm"] = {
            "status": "degraded" if has_open_circuit else "ok",
            **llm_status,
        }
    except Exception as e:
        checks["llm"] = {"status": "error", "detail": str(e)[:100]}

    statuses = [c.get("status") for c in checks.values()]
    if all(s in ("ok", "unconfigured", "no_workers") for s in statuses):
        overall = "healthy"
    elif any(s in ("error", "degraded") for s in statuses):
        overall = "degraded"
    else:
        overall = "healthy"

    return {
        "status": overall,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "0.5.0",
        "checks": checks,
    }


# Model presets for quick switching.
MODEL_PRESETS = {
    "deepseek": {
        "provider": "deepseek",
        "model": "deepseek-v4-flash",
        "base_url": "",
        "label": "DeepSeek API",
    },
}


class ModelSwitchRequest(BaseModel):
    preset: Optional[str] = None
    model: Optional[str] = None
    base_url: Optional[str] = None


async def _validate_llm_backend(model: str, base_url: str) -> None:
    """Best-effort preflight for OpenAI-compatible endpoints."""
    if not base_url:
        return

    import httpx

    models_url = f"{base_url.rstrip('/')}/models"
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(models_url)
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"无法连接到目标 LLM 服务 {base_url}: {e}")

    if resp.status_code >= 400:
        raise HTTPException(status_code=503, detail=f"目标 LLM 服务返回 HTTP {resp.status_code}")

    try:
        payload = resp.json()
    except Exception:
        return

    if isinstance(payload, dict):
        model_ids: list[str] = []
        for item in payload.get("data") or []:
            if isinstance(item, dict) and item.get("id"):
                model_ids.append(str(item["id"]))
        if model_ids:
            normalized = model.strip()
            if not any(
                candidate == normalized
                or candidate.endswith(f"/{normalized}")
                or normalized.endswith(f"/{candidate}")
                for candidate in model_ids
            ):
                logger.warning(
                    "LLM validation mismatch: requested=%s available=%s base_url=%s",
                    model,
                    model_ids,
                    base_url,
                )
                raise HTTPException(
                    status_code=503,
                    detail=f"目标 LLM 服务已响应，但未找到模型 {model}。可用模型: {', '.join(model_ids[:5])}",
                )


@router.post("/llm/switch")
@router.post("/api/v1/llm/switch")
async def switch_llm_model(
    req: ModelSwitchRequest,
    _perm: None = Depends(require_permission(Permission.SYSTEM_CONFIG, auth=Depends(get_current_user))),
):
    """Switch the active LLM model at runtime (no restart needed)."""
    try:
        from app.llm.router import router as llm_router

        if req.preset:
            preset = MODEL_PRESETS.get(req.preset)
            if not preset:
                raise HTTPException(
                    status_code=400,
                    detail=f"Unknown preset: {req.preset}. Available: {list(MODEL_PRESETS.keys())}",
                )
            model = preset["model"]
            base_url = preset["base_url"]
        elif req.model:
            model = req.model
            base_url = req.base_url or ""
        else:
            raise HTTPException(status_code=400, detail="Provide 'preset' or 'model'")

        await _validate_llm_backend(model, base_url)
        result = llm_router.switch_model(model, base_url)
        return {"ok": True, "config": result}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/llm/models")
@router.get("/api/v1/llm/models")
async def list_model_presets():
    """List available model presets and current config."""
    try:
        from app.llm.router import router as llm_router

        current = llm_router.status()
        return {
            "current": {
                "model": current["default_model"],
                "base_url": current.get("base_url", "api"),
                "provider_hint": current.get("provider_hint", "auto"),
                "auth": current.get("auth", {}),
            },
            "presets": MODEL_PRESETS,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
