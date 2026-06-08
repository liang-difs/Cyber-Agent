"""Assets API — CMDB asset management."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.api.deps import get_current_user, scoped_tenant
from app.rbac.permissions import Permission, require_permission

router = APIRouter(prefix="/api/v1/assets", tags=["assets"])


def _get_current_user(user: dict = Depends(get_current_user)) -> dict:
    return user


def _serialize_asset(asset) -> dict:
    return {
        "id": asset.id,
        "name": asset.name,
        "asset_type": asset.asset_type,
        "ip_address": asset.ip_address,
        "hostname": asset.hostname,
        "os": asset.os,
        "owner": asset.owner,
        "department": asset.department,
        "criticality": asset.criticality,
        "status": asset.status,
        "tags": asset.tags,
        "notes": asset.notes,
        "created_at": asset.created_at.isoformat() if asset.created_at else None,
        "updated_at": asset.updated_at.isoformat() if asset.updated_at else None,
    }


class AssetCreate(BaseModel):
    name: str
    asset_type: str = "host"
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    os: Optional[str] = None
    owner: Optional[str] = None
    department: Optional[str] = None
    criticality: str = "medium"
    tags: Optional[list] = None
    notes: Optional[str] = None


class AssetUpdate(BaseModel):
    name: Optional[str] = None
    asset_type: Optional[str] = None
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    os: Optional[str] = None
    owner: Optional[str] = None
    department: Optional[str] = None
    criticality: Optional[str] = None
    status: Optional[str] = None
    tags: Optional[list] = None
    notes: Optional[str] = None


@router.get("")
async def list_assets(
    asset_type: Optional[str] = None,
    criticality: Optional[str] = None,
    status: Optional[str] = None,
    keyword: Optional[str] = None,
    limit: int = Query(default=50, le=500),
    offset: int = 0,
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.ALERT_VIEW, auth=Depends(_get_current_user))),
):
    """List assets with optional filtering."""
    try:
        from app.models.base import get_session_factory
        from app.models.models import Asset
        from sqlalchemy import select, func, or_

        factory = get_session_factory()
        if factory is None:
            return {"assets": [], "total": 0}

        async with factory() as session:
            tenant_id = scoped_tenant(user)
            query = select(Asset).where(Asset.tenant_id == tenant_id)
            count_query = select(func.count(Asset.id)).where(Asset.tenant_id == tenant_id)

            if asset_type:
                query = query.where(Asset.asset_type == asset_type)
                count_query = count_query.where(Asset.asset_type == asset_type)
            if criticality:
                query = query.where(Asset.criticality == criticality)
                count_query = count_query.where(Asset.criticality == criticality)
            if status:
                query = query.where(Asset.status == status)
                count_query = count_query.where(Asset.status == status)
            if keyword:
                like = f"%{keyword}%"
                filter_cond = or_(
                    Asset.name.ilike(like),
                    Asset.ip_address.ilike(like),
                    Asset.hostname.ilike(like),
                    Asset.owner.ilike(like),
                )
                query = query.where(filter_cond)
                count_query = count_query.where(filter_cond)

            total = (await session.execute(count_query)).scalar() or 0
            query = query.order_by(Asset.updated_at.desc()).offset(offset).limit(limit)
            rows = (await session.execute(query)).scalars().all()

        return {"assets": [_serialize_asset(a) for a in rows], "total": total, "limit": limit, "offset": offset}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("")
async def create_asset(
    req: AssetCreate,
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.TASK_SUBMIT, auth=Depends(_get_current_user))),
):
    """Create a new asset."""
    try:
        from app.models.base import get_session_factory
        from app.models.models import Asset

        factory = get_session_factory()
        if factory is None:
            raise HTTPException(status_code=503, detail="Database not available")

        async with factory() as session:
            tenant_id = scoped_tenant(user)
            asset = Asset(
                tenant_id=tenant_id,
                name=req.name,
                asset_type=req.asset_type,
                ip_address=req.ip_address,
                hostname=req.hostname,
                os=req.os,
                owner=req.owner,
                department=req.department,
                criticality=req.criticality,
                tags=req.tags,
                notes=req.notes,
            )
            session.add(asset)
            await session.commit()
            await session.refresh(asset)
        return _serialize_asset(asset)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{asset_id}")
async def get_asset(
    asset_id: str,
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.ALERT_VIEW, auth=Depends(_get_current_user))),
):
    """Get a single asset by ID."""
    try:
        from app.models.base import get_session_factory
        from app.models.models import Asset
        from sqlalchemy import select

        factory = get_session_factory()
        if factory is None:
            raise HTTPException(status_code=503, detail="Database not available")

        async with factory() as session:
            tenant_id = scoped_tenant(user)
            result = await session.execute(
                select(Asset).where(Asset.id == asset_id, Asset.tenant_id == tenant_id)
            )
            asset = result.scalar_one_or_none()
            if not asset:
                raise HTTPException(status_code=404, detail="Asset not found")
        return _serialize_asset(asset)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{asset_id}")
async def update_asset(
    asset_id: str,
    req: AssetUpdate,
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.TASK_SUBMIT, auth=Depends(_get_current_user))),
):
    """Update an asset."""
    try:
        from app.models.base import get_session_factory
        from app.models.models import Asset
        from sqlalchemy import select
        from datetime import datetime, timezone

        factory = get_session_factory()
        if factory is None:
            raise HTTPException(status_code=503, detail="Database not available")

        async with factory() as session:
            tenant_id = scoped_tenant(user)
            result = await session.execute(
                select(Asset).where(Asset.id == asset_id, Asset.tenant_id == tenant_id)
            )
            asset = result.scalar_one_or_none()
            if not asset:
                raise HTTPException(status_code=404, detail="Asset not found")

            for field, value in req.model_dump(exclude_unset=True).items():
                setattr(asset, field, value)
            asset.updated_at = datetime.now(timezone.utc)
            await session.commit()
            await session.refresh(asset)
        return _serialize_asset(asset)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{asset_id}")
async def delete_asset(
    asset_id: str,
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.TASK_SUBMIT, auth=Depends(_get_current_user))),
):
    """Delete an asset."""
    try:
        from app.models.base import get_session_factory
        from app.models.models import Asset
        from sqlalchemy import select

        factory = get_session_factory()
        if factory is None:
            raise HTTPException(status_code=503, detail="Database not available")

        async with factory() as session:
            tenant_id = scoped_tenant(user)
            result = await session.execute(
                select(Asset).where(Asset.id == asset_id, Asset.tenant_id == tenant_id)
            )
            asset = result.scalar_one_or_none()
            if not asset:
                raise HTTPException(status_code=404, detail="Asset not found")
            await session.delete(asset)
            await session.commit()
        return {"ok": True}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/lookup/ip/{ip}")
async def lookup_asset_by_ip(
    ip: str,
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.ALERT_VIEW, auth=Depends(_get_current_user))),
):
    """Look up assets by IP address — used by alert assessment."""
    try:
        from app.models.base import get_session_factory
        from app.models.models import Asset
        from sqlalchemy import select

        factory = get_session_factory()
        if factory is None:
            return {"assets": []}

        async with factory() as session:
            tenant_id = scoped_tenant(user)
            result = await session.execute(
                select(Asset).where(Asset.ip_address == ip, Asset.tenant_id == tenant_id)
            )
            assets = result.scalars().all()
        return {"assets": [_serialize_asset(a) for a in assets]}
    except Exception:
        return {"assets": []}
