"""Tests for analysis API endpoints."""

import pytest
from unittest.mock import patch, MagicMock
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.api.analysis import _get_current_user as analysis_auth
from app.api.reports import _get_current_user as reports_auth
from app.api.audit import _get_current_user as audit_auth


@pytest.mark.anyio
async def test_attack_chains_no_db():
    """Attack chains endpoint returns gracefully without DB."""
    app.dependency_overrides[analysis_auth] = lambda: {"user_id": "u1", "role": "analyst"}
    try:
        with patch("app.models.base.get_session_factory", return_value=None):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/v1/analysis/attack-chains",
                    json={"tenant_id": "test"},
                    headers={"Authorization": "Bearer test"},
                )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_alerts"] == 0
        assert "warning" in data
    finally:
        app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_correlate_no_db():
    """Correlation endpoint returns gracefully without DB."""
    app.dependency_overrides[analysis_auth] = lambda: {"user_id": "u1", "role": "analyst"}
    try:
        with patch("app.models.base.get_session_factory", return_value=None):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/v1/analysis/correlate",
                    json={"tenant_id": "test"},
                    headers={"Authorization": "Bearer test"},
                )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_alerts"] == 0
    finally:
        app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_generate_report_no_db():
    """Report endpoint returns error without DB."""
    app.dependency_overrides[reports_auth] = lambda: {"user_id": "u1", "role": "analyst"}
    try:
        with patch("app.models.base.get_session_factory", return_value=None):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/v1/reports/generate",
                    json={"title": "Test Report", "tenant_id": "test"},
                    headers={"Authorization": "Bearer test"},
                )
        # Without DB, returns 503 or 500 depending on error path
        assert resp.status_code in (500, 503)
    finally:
        app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_audit_logs_requires_admin():
    """Audit logs endpoint requires admin role."""
    app.dependency_overrides[audit_auth] = lambda: {"user_id": "u1", "role": "analyst"}
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/audit/logs",
                headers={"Authorization": "Bearer test"},
            )
        assert resp.status_code == 403
    finally:
        app.dependency_overrides.clear()
