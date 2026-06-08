"""Audit logging middleware — records all API actions to AuditLog table."""

from __future__ import annotations

import logging
import time
from typing import Callable, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.deps import normalize_user
from app.core.config import get_settings
from app.core.security import verify_token

logger = logging.getLogger(__name__)

# Paths to skip logging (health checks, static, and high-frequency chat paths)
SKIP_PATHS = {
    "/health",
    "/metrics",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/api/v1/agent/chat",
    "/api/v1/agent/sessions",
}

# Map HTTP methods to audit actions
ACTION_MAP = {
    "GET": "read",
    "POST": "create",
    "PUT": "update",
    "PATCH": "update",
    "DELETE": "delete",
}


def _get_client_ip(request: Request) -> str:
    """Extract client IP from request, respecting X-Forwarded-For."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class AuditMiddleware(BaseHTTPMiddleware):
    """Logs API requests to the audit_logs table."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        # Skip non-audit paths
        if any(path.startswith(p) for p in SKIP_PATHS):
            return await call_next(request)

        self._attach_user_from_header(request)

        start = time.time()
        response = await call_next(request)
        duration_ms = int((time.time() - start) * 1000)

        # Extract user info from request state (set by auth dependency)
        user = getattr(request.state, "user", None)
        user_id = (user.get("user_id") or user.get("sub")) if user else None
        tenant_id = user.get("tenant_id", "default") if user else "default"

        action = ACTION_MAP.get(request.method, "unknown")
        resource = f"{request.method} {path}"

        # Build detail
        detail = {
            "status_code": response.status_code,
            "duration_ms": duration_ms,
        }
        if request.query_params:
            detail["query"] = dict(request.query_params)

        # Write to DB (fire-and-forget style with error suppression)
        try:
            await self._write_audit(
                user_id=user_id,
                action=action,
                resource=resource,
                detail=detail,
                ip_address=_get_client_ip(request),
                tenant_id=tenant_id,
            )
        except Exception as e:
            logger.warning("Audit log write failed: %s", e)

        return response

    @staticmethod
    def _attach_user_from_header(request: Request) -> None:
        """Best-effort JWT decoding so audit logs include user and tenant."""
        authorization = request.headers.get("authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            return
        try:
            settings = get_settings()
            payload = verify_token(token, secret=settings.jwt_secret, algorithm=settings.jwt_algorithm)
            if payload:
                request.state.user = normalize_user(payload)
        except Exception:
            return

    @staticmethod
    async def _write_audit(
        user_id: Optional[str],
        action: str,
        resource: str,
        detail: dict,
        ip_address: str,
        tenant_id: str,
    ) -> None:
        """Write audit record to database."""
        from app.models.base import get_session_factory
        from app.models.models import AuditLog

        factory = get_session_factory()
        if factory is None:
            return

        async with factory() as session:
            log = AuditLog(
                user_id=user_id,
                action=action,
                resource=resource,
                detail=detail,
                ip_address=ip_address,
                tenant_id=tenant_id,
            )
            session.add(log)
            await session.commit()
