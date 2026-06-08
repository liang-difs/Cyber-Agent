"""Shared API dependencies for authentication and tenant scoping."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import Header, HTTPException, Request

from app.core.config import get_settings
from app.core.security import verify_token


def normalize_user(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a consistent user dict from JWT payload or test overrides."""
    user_id = payload.get("user_id") or payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    return {
        **payload,
        "user_id": user_id,
        "sub": payload.get("sub") or user_id,
        "role": payload.get("role", "viewer"),
        "tenant_id": payload.get("tenant_id", "default"),
    }


def get_current_user(
    request: Request,
    authorization: Optional[str] = Header(None),
) -> dict[str, Any]:
    """Verify the bearer token and attach the normalized user to request state."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Not authenticated")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    settings = get_settings()
    payload = verify_token(token, secret=settings.jwt_secret, algorithm=settings.jwt_algorithm)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = normalize_user(payload)
    request.state.user = user
    return user


def scoped_tenant(user: dict[str, Any]) -> str:
    """Tenant id is always derived from the authenticated principal."""
    return normalize_user(user)["tenant_id"]
