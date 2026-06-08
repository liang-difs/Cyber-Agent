"""IoC Bulk API — batch threat intelligence lookups."""

from __future__ import annotations

import asyncio
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.api.deps import get_current_user, scoped_tenant
from app.rbac.permissions import Permission, require_permission

router = APIRouter(prefix="/api/v1/ioc", tags=["ioc"])


def _get_current_user(user: dict = Depends(get_current_user)) -> dict:
    return user


def _detect_ioc_type(value: str) -> str:
    """Auto-detect IoC type from value."""
    import re
    v = value.strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
        return "ip"
    if re.match(r"^[a-fA-F0-9]{32,64}$", v):
        return "hash"
    if re.match(r"^https?://", v):
        return "url"
    if "." in v and not v[0].isdigit():
        return "domain"
    return "ip"


class BulkIoCRequest(BaseModel):
    indicators: list[str]  # List of IPs, domains, hashes, or URLs
    max_concurrent: int = 5


class IoCResult(BaseModel):
    indicator: str
    ioc_type: str
    success: bool
    risk_level: Optional[str] = None
    data: Optional[dict] = None
    error: Optional[str] = None


@router.post("/bulk-lookup")
async def bulk_ioc_lookup(
    req: BulkIoCRequest,
    user: dict = Depends(_get_current_user),
    _perm: None = Depends(require_permission(Permission.TOOL_IOC, auth=Depends(_get_current_user))),
):
    """Batch IoC lookup — query multiple indicators concurrently."""
    if len(req.indicators) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 indicators per request")

    from app.tools.ioc_tool import IoCLookupTool, IoCInput
    import uuid

    tool = IoCLookupTool()
    tenant_id = scoped_tenant(user)
    semaphore = asyncio.Semaphore(req.max_concurrent)

    async def lookup_one(indicator: str) -> IoCResult:
        indicator = indicator.strip()
        if not indicator:
            return IoCResult(indicator=indicator, ioc_type="unknown", success=False, error="Empty indicator")

        ioc_type = _detect_ioc_type(indicator)
        async with semaphore:
            try:
                input_data = IoCInput(
                    value=indicator,
                    type=ioc_type,
                    trace_id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                )
                result = await tool.execute(input_data)
                data = result.data if result.success else None
                return IoCResult(
                    indicator=indicator,
                    ioc_type=ioc_type,
                    success=result.success,
                    risk_level=data.get("risk_level") if data else None,
                    data=data,
                    error=result.error,
                )
            except Exception as e:
                return IoCResult(indicator=indicator, ioc_type=ioc_type, success=False, error=str(e))

    results = await asyncio.gather(*[lookup_one(ind) for ind in req.indicators])

    return {
        "results": [r.model_dump() for r in results],
        "total": len(results),
        "success_count": sum(1 for r in results if r.success),
    }
