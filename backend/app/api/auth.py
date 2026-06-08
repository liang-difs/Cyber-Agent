"""Authentication endpoints."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from app.core.config import get_settings
from app.core.security import create_access_token, hash_password, verify_password
from app.models.models import User

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
logger = logging.getLogger(__name__)

# Development fallback user. Production should set AUTH_DEV_FALLBACK_ENABLED=false.
_DEV_USERS: dict[str, dict] = {
    "admin": {
        "id": "00000000-0000-0000-0000-000000000001",
        "username": "admin",
        "hashed_password": hash_password("admin123"),
        "role": "admin",
        "tenant_id": "tenant-1",
    }
}


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    role: str
    tenant_id: str


async def _get_db_user(username: str) -> dict | None:
    """Load an active user from PostgreSQL. Returns None if DB is unavailable."""
    try:
        from app.models.base import get_session_factory

        factory = get_session_factory()
        async with factory() as session:
            result = await session.execute(
                select(User).where(User.username == username, User.is_active.is_(True))
            )
            user = result.scalar_one_or_none()
            if not user:
                return None
            return {
                "id": user.id,
                "username": user.username,
                "hashed_password": user.hashed_password,
                "role": user.role,
                "tenant_id": user.tenant_id,
            }
    except Exception as e:
        logger.info("Database auth lookup unavailable for %s: %s", username, e)
        return None


async def _get_login_user(username: str, password: str) -> dict | None:
    """Authenticate against DB first, then optional development fallback."""
    user = await _get_db_user(username)
    if user and verify_password(password, user["hashed_password"]):
        return user

    settings = get_settings()
    if settings.auth_dev_fallback_enabled:
        fallback_user = _DEV_USERS.get(username)
        if fallback_user and verify_password(password, fallback_user["hashed_password"]):
            return fallback_user
    return None


@router.post("/login", response_model=LoginResponse)
async def login(req: LoginRequest):
    user = await _get_login_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    settings = get_settings()
    token = create_access_token(
        data={"sub": user["id"], "role": user["role"], "tenant_id": user["tenant_id"]},
        secret=settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        expires_minutes=settings.jwt_expire_minutes,
    )

    return LoginResponse(
        access_token=token,
        user_id=user["id"],
        role=user["role"],
        tenant_id=user["tenant_id"],
    )
