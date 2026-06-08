"""User management API — admin only."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.api.deps import get_current_user, scoped_tenant
from app.core.security import hash_password
from app.rbac.permissions import Permission, require_permission

router = APIRouter(prefix="/api/v1/users", tags=["users"])


def _get_current_user(user: dict = Depends(get_current_user)) -> dict:
    return user


def _serialize_user(user) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "tenant_id": user.tenant_id,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None,
    }


class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "analyst"
    email: Optional[str] = None


class UserUpdate(BaseModel):
    role: Optional[str] = None
    email: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None


@router.get("")
async def list_users(
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.USER_MANAGE, auth=Depends(_get_current_user))),
):
    """List all users in the tenant (admin only)."""
    try:
        from app.models.base import get_session_factory
        from app.models.models import User
        from sqlalchemy import select, func

        factory = get_session_factory()
        if factory is None:
            return {"users": [], "total": 0}

        tenant_id = scoped_tenant(user)
        async with factory() as session:
            total = (await session.execute(
                select(func.count(User.id)).where(User.tenant_id == tenant_id)
            )).scalar() or 0

            query = (
                select(User)
                .where(User.tenant_id == tenant_id)
                .order_by(User.created_at.desc())
                .offset(offset)
                .limit(limit)
            )
            rows = (await session.execute(query)).scalars().all()

        return {"users": [_serialize_user(u) for u in rows], "total": total}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("")
async def create_user(
    req: UserCreate,
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.USER_MANAGE, auth=Depends(_get_current_user))),
):
    """Create a new user (admin only)."""
    if req.role not in ("admin", "analyst", "viewer"):
        raise HTTPException(status_code=400, detail=f"Invalid role: {req.role}")
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    try:
        from app.models.base import get_session_factory
        from app.models.models import User
        from sqlalchemy import select

        factory = get_session_factory()
        if factory is None:
            raise HTTPException(status_code=503, detail="Database not available")

        tenant_id = scoped_tenant(user)
        async with factory() as session:
            # Check username uniqueness
            existing = await session.execute(select(User).where(User.username == req.username))
            if existing.scalar_one_or_none():
                raise HTTPException(status_code=409, detail=f"Username '{req.username}' already exists")

            new_user = User(
                username=req.username,
                email=req.email,
                hashed_password=hash_password(req.password),
                role=req.role,
                tenant_id=tenant_id,
                is_active=True,
            )
            session.add(new_user)
            await session.commit()
            await session.refresh(new_user)
        return _serialize_user(new_user)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{user_id}")
async def update_user(
    user_id: str,
    req: UserUpdate,
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.USER_MANAGE, auth=Depends(_get_current_user))),
):
    """Update a user's role, status, email, or password (admin only)."""
    if req.role is not None and req.role not in ("admin", "analyst", "viewer"):
        raise HTTPException(status_code=400, detail=f"Invalid role: {req.role}")
    if req.password is not None and len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    try:
        from app.models.base import get_session_factory
        from app.models.models import User
        from sqlalchemy import select
        from datetime import datetime, timezone

        factory = get_session_factory()
        if factory is None:
            raise HTTPException(status_code=503, detail="Database not available")

        tenant_id = scoped_tenant(user)
        async with factory() as session:
            result = await session.execute(
                select(User).where(User.id == user_id, User.tenant_id == tenant_id)
            )
            target = result.scalar_one_or_none()
            if not target:
                raise HTTPException(status_code=404, detail="User not found")

            if req.role is not None:
                target.role = req.role
            if req.email is not None:
                target.email = req.email
            if req.is_active is not None:
                target.is_active = req.is_active
            if req.password is not None:
                target.hashed_password = hash_password(req.password)
            target.updated_at = datetime.now(timezone.utc)

            await session.commit()
            await session.refresh(target)
        return _serialize_user(target)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.USER_MANAGE, auth=Depends(_get_current_user))),
):
    """Delete a user (admin only). Cannot delete yourself."""
    try:
        from app.models.base import get_session_factory
        from app.models.models import User
        from sqlalchemy import select

        factory = get_session_factory()
        if factory is None:
            raise HTTPException(status_code=503, detail="Database not available")

        current_user_id = user.get("user_id") or user.get("sub")
        if user_id == current_user_id:
            raise HTTPException(status_code=400, detail="Cannot delete yourself")

        tenant_id = scoped_tenant(user)
        async with factory() as session:
            result = await session.execute(
                select(User).where(User.id == user_id, User.tenant_id == tenant_id)
            )
            target = result.scalar_one_or_none()
            if not target:
                raise HTTPException(status_code=404, detail="User not found")

            await session.delete(target)
            await session.commit()
        return {"ok": True}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
