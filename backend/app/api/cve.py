"""CVE REST API endpoints."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query

router = APIRouter(prefix="/api/v1/cve", tags=["cve"])


def _get_bm25():
    """Get BM25 singleton instance."""
    from app.rag.bm25_search import bm25_instance
    return bm25_instance


@router.get("/list")
async def list_cves(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    keyword: Optional[str] = None,
) -> dict[str, Any]:
    """List CVEs with pagination and filtering."""
    bm25 = _get_bm25()
    return bm25.list_all(page=page, page_size=page_size, severity=severity, keyword=keyword)


@router.get("/stats")
async def cve_stats() -> dict[str, Any]:
    """CVE severity distribution and recent items."""
    bm25 = _get_bm25()
    return bm25.stats()


@router.get("/{cve_id}")
async def get_cve(cve_id: str) -> dict[str, Any]:
    """Get a single CVE by ID."""
    bm25 = _get_bm25()
    item = bm25.get_by_id(cve_id)
    if not item:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    return item
